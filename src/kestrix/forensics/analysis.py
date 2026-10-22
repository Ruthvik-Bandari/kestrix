# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Streamed, bounded static analysis of one file: hashes, entropy, format and findings.

Nothing here executes, decompresses or renders the file. Memory stays bounded by one
read chunk, a 64 KiB header sample and one float per 4 KiB block.
"""

from __future__ import annotations

import codecs
import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import BinaryIO

from ..core.errors import Reason, Rejected
from .exif import exif_findings, read_exif
from .models import (
    EntropyPoint,
    EntropyProfile,
    EntropyRegion,
    ExifData,
    ExifStatus,
    FileReport,
    FileType,
    Finding,
    Hashes,
    Severity,
    by_severity,
)

MIB = 1024 * 1024
MAX_FILE_BYTES = 50 * MIB
CHUNK_BYTES = MIB
BLOCK_BYTES = 4096
HEAD_BYTES = 64 * 1024
TAIL_BYTES = 64 * 1024
MAX_ENTROPY_POINTS = 512
HIGH_ENTROPY_BITS = 7.2
MIN_REGION_BLOCKS = 2
MAX_REGIONS = 32
MAX_PE_CANDIDATES = 64
MAX_E_LFANEW = 0x400

_PRINTABLE = frozenset({9, 10, 13, *range(32, 127)})
_TEXT_CONTROLS = frozenset({9, 10, 12, 13, 27})
# Unicode bidirectional embedding, override and isolate controls (U+202A-U+202E, U+2066-U+2069).
_BIDI_CONTROLS = frozenset(map(chr, [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]))


@dataclass(frozen=True)
class Kind:
    """A file format recognised from its content."""

    id: str
    label: str
    extensions: frozenset[str]
    executable: bool = False
    compressed: bool = False  # the format normally holds compressed data, so high entropy is expected


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


def _kind(kind_id: str, label: str, extensions: str, *, executable: bool = False, compressed: bool = False) -> Kind:
    return Kind(kind_id, label, _words(extensions), executable, compressed)


_PROGRAM = "exe dll sys scr com ocx cpl efi drv mui node"
_MACHO = "dylib bundle so o kext node"
KINDS = {
    k.id: k
    for k in (
        _kind("pe", "Windows program (PE executable)", _PROGRAM, executable=True),
        _kind("dos_mz", "DOS or unrecognised MZ executable", _PROGRAM, executable=True),
        _kind("elf", "Linux/Unix program (ELF executable)", "so o elf bin ko out axf prx", executable=True),
        _kind("macho", "macOS program (Mach-O executable)", _MACHO, executable=True),
        _kind("macho_fat", "macOS universal program (Mach-O fat binary)", _MACHO, executable=True),
        _kind("script", "Script", "sh bash zsh ksh csh py pl rb php js mjs command tcl lua awk", executable=True),
        _kind("java_class", "Java class file", "class"),
        _kind("wasm", "WebAssembly module", "wasm"),
        _kind("pdf", "PDF document", "pdf", compressed=True),
        _kind("docx", "Word document (Office Open XML)", "docx docm dotx dotm", compressed=True),
        _kind("xlsx", "Excel workbook (Office Open XML)", "xlsx xlsm xltx xltm", compressed=True),
        _kind("pptx", "PowerPoint presentation (Office Open XML)", "pptx pptm potx potm ppsx ppsm", compressed=True),
        _kind(
            "ooxml",
            "Office Open XML document",
            "docx docm dotx dotm xlsx xlsm xltx xltm pptx pptm potx potm ppsx ppsm vsdx",
            compressed=True,
        ),
        _kind(
            "zip",
            "ZIP archive",
            "zip jar apk aar war ear ipa xpi epub odt ods odp odg whl nupkg vsix kmz appx msix 3mf",
            compressed=True,
        ),
        _kind(
            "ole2",
            "Legacy Office or Installer file (OLE2)",
            "doc dot xls xlt ppt pps pot msi msg vsd pub",
            compressed=True,  # legacy Office files embed compressed images and objects
        ),
        _kind("png", "PNG image", "png", compressed=True),
        _kind("jpeg", "JPEG image", "jpg jpeg jpe jfif", compressed=True),
        _kind("gif", "GIF image", "gif", compressed=True),
        _kind("webp", "WebP image", "webp", compressed=True),
        _kind("tiff", "TIFF image", "tif tiff dng"),
        _kind("gzip", "gzip compressed data", "gz tgz gzip", compressed=True),
        _kind("bzip2", "bzip2 compressed data", "bz2 tbz tbz2", compressed=True),
        _kind("xz", "xz compressed data", "xz txz", compressed=True),
        _kind("7z", "7-Zip archive", "7z", compressed=True),
        _kind("rar", "RAR archive", "rar", compressed=True),
        _kind("swf", "Adobe Flash movie (SWF)", "swf spl", compressed=True),
        _kind("sqlite", "SQLite database", "db sqlite sqlite3 db3"),
        _kind("text", "Plain text", ""),
        _kind("empty", "Empty file", ""),
        _kind("unknown", "Unrecognised format", ""),
    )
}

_PREFIXES = (
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (b"\x00asm", "wasm"),
    (b"SQLite format 3\x00", "sqlite"),
)
_OOXML_PARTS = ((b"word/", "docx"), (b"xl/", "xlsx"), (b"ppt/", "pptx"))
# Extensions of formats that are never plain text; text content under one of them is a mismatch.
_BINARY_ONLY = _words(
    "exe dll sys scr pdf png jpg jpeg gif webp tif tiff zip gz 7z rar docx xlsx pptx doc xls ppt msi so dylib "
    "class wasm sqlite mp3 mp4 mov avi"
)
_EXIF_KINDS = frozenset({"jpeg", "png", "tiff", "webp"})
_OFFICE_KINDS = frozenset({"docx", "xlsx", "pptx", "ooxml"})
_MACRO_PART = b"vbaProject.bin"
# Office Open XML extensions that promise a document without macros (Word and Excel refuse a macro part there).
_MACRO_FREE = _words("docx xlsx pptx dotx xltx potx ppsx")
# Formats that never hold a program: one found inside is an appended or smuggled payload.
_NO_PROGRAM_KINDS = frozenset({"pdf", "jpeg", "png", "gif", "webp", "tiff", "docx", "xlsx", "pptx", "ooxml"})
_SVG = re.compile(rb"<svg[\s>]", re.IGNORECASE)
_ACTIVE = re.compile(rb"<script|javascript:|\bon(?:load|error|click|mouseover|begin)\s*=", re.IGNORECASE)
# Script files Windows runs on a double click (JavaScript is common on the web, so it is only a low signal).
_WINDOWS_SCRIPTS = _words("vbs vbe jse wsf wsh hta bat cmd ps1 psm1 scf")
# Double-extension lure: a document-like name followed by an extension Windows will run.
_RUNNABLE = _words("exe scr com bat cmd pif js jse vbs vbe wsf hta msi lnk ps1 jar")
_DECOY = _words("pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif mp3 mp4 avi mov zip rar csv")
_DISGUISED = "Renaming programs to look like documents or images is a common malware trick."
_MISNAMED = "It may be an honest mistake, or an attempt to slip the file past filters."


@dataclass(frozen=True)
class _Scan:
    size: int
    hashes: Hashes
    histogram: list[int]
    block_entropy: list[float]
    head: bytes
    tail: bytes


def analyze_file(stream: BinaryIO, filename: str, max_bytes: int = MAX_FILE_BYTES) -> FileReport:
    """Analyse a readable, seekable binary stream positioned at its start.

    Raises ``Rejected(INPUT_TOO_LARGE)`` once more than ``max_bytes`` have been read.
    """
    name = display_name(filename)
    scan = _scan(stream, max_bytes)
    kind = detect_kind(scan.head)
    extension = file_extension(name)
    mismatch = extension_mismatch(kind, extension)
    entropy = _entropy_profile(scan)
    exif_status: ExifStatus = "not_image"
    exif: ExifData | None = None
    if kind.id in _EXIF_KINDS:
        stream.seek(0)
        exif_status, exif = read_exif(stream)
    findings = [
        *_name_findings(filename, name),
        *_type_findings(kind, extension, mismatch),
        *_content_findings(kind, extension, scan),
        *_entropy_findings(kind, entropy, scan.size),
        *(exif_findings(exif) if exif else []),
    ]
    return FileReport(
        filename=name,
        size=scan.size,
        hashes=scan.hashes,
        file_type=FileType(
            id=kind.id,
            label=kind.label,
            executable=kind.executable,
            extension=extension,
            expected_extensions=sorted(kind.extensions),
            extension_mismatch=mismatch,
        ),
        entropy=entropy,
        byte_histogram=scan.histogram,
        printable_ratio=round(sum(scan.histogram[b] for b in _PRINTABLE) / scan.size, 4) if scan.size else 0.0,
        exif=exif,
        exif_status=exif_status,
        findings=by_severity(findings),
    )


def shannon_entropy(counts: Iterable[int], total: int) -> float:
    """Bits per byte: 0 for a single repeated value, up to 8 when all 256 values are equally common."""
    if total <= 0:
        return 0.0
    return sum(count / total * math.log2(total / count) for count in counts if count)


def downsample(values: Sequence[float], max_points: int = MAX_ENTROPY_POINTS) -> tuple[int, list[float]]:
    """Average consecutive values so at most ``max_points`` remain; return (span, means)."""
    span = max(1, math.ceil(len(values) / max_points))
    means = []
    for start in range(0, len(values), span):
        group = values[start : start + span]
        means.append(sum(group) / len(group))
    return span, means


def high_entropy_regions(
    block_entropy: Sequence[float], size: int, threshold: float = HIGH_ENTROPY_BITS
) -> list[EntropyRegion]:
    """Runs of at least ``MIN_REGION_BLOCKS`` consecutive blocks at or above ``threshold``."""
    regions = []
    start: int | None = None
    for index, value in enumerate([*block_entropy, 0.0]):  # the sentinel closes a run reaching the end
        if value >= threshold:
            if start is None:
                start = index
            continue
        if start is not None and index - start >= MIN_REGION_BLOCKS:
            run = block_entropy[start:index]
            regions.append(
                EntropyRegion(
                    start=start * BLOCK_BYTES,
                    end=min(index * BLOCK_BYTES, size),
                    mean_entropy=round(sum(run) / len(run), 4),
                )
            )
        start = None
    return regions


def detect_kind(head: bytes) -> Kind:
    """Identify the format from the first bytes of the content, never from the name."""
    if not head:
        return KINDS["empty"]
    if head.startswith(b"MZ"):
        return KINDS["pe" if _has_pe_header(head) else "dos_mz"]
    if head.startswith(b"\xca\xfe\xba\xbe"):
        # Shared by Mach-O fat binaries (small architecture count) and Java classes (version >= 45).
        return KINDS["macho_fat" if int.from_bytes(head[4:8], "big") < 45 else "java_class"]
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return _zip_kind(head)
    if head[:3] in (b"CWS", b"ZWS", b"FWS") and len(head) > 8 and head[3] < 64 and not _looks_like_text(head[:32]):
        return KINDS["swf"]
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return KINDS["webp"]
    for magic, kind_id in _PREFIXES:
        if head.startswith(magic):
            return KINDS[kind_id]
    if b"%PDF-" in head[:1024]:  # readers accept junk before the header, so search the first KiB
        return KINDS["pdf"]
    if head.startswith(b"#!"):
        first_line = head[2:].split(b"\n", 1)[0].decode("latin-1")
        interpreter = "".join(ch for ch in first_line if ch.isprintable()).strip()[:80]
        return replace(KINDS["script"], label=f"Script for {interpreter or 'an unnamed interpreter'}")
    return KINDS["text" if _looks_like_text(head) else "unknown"]


def file_extension(name: str) -> str | None:
    suffixes = [suffix[1:].strip().lower() for suffix in PurePosixPath(name).suffixes]
    if not suffixes:
        return None
    if suffixes[-1].isdigit() and "so" in suffixes:  # versioned shared library, e.g. libc.so.6
        return "so"
    return suffixes[-1] or None


def extension_mismatch(kind: Kind, extension: str | None) -> bool:
    if extension is None or kind.id in {"unknown", "empty"}:
        return False
    if kind.id == "text":
        return extension in _BINARY_ONLY
    return extension not in kind.extensions


def display_name(filename: str) -> str:
    """Base name with directories and invisible or control characters removed."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return "".join(ch for ch in base if ch.isprintable())[:255] or "upload"


def _scan(stream: BinaryIO, max_bytes: int) -> _Scan:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    histogram = [0] * 256
    block_entropy: list[float] = []
    head = bytearray()
    tail = b""
    carry = b""
    size = 0
    while chunk := stream.read(CHUNK_BYTES):
        size += len(chunk)
        if size > max_bytes:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"file is larger than the {max_bytes:,} byte limit")
        for hasher in (md5, sha1, sha256, sha512):
            hasher.update(chunk)
        if len(head) < HEAD_BYTES:
            head += chunk[: HEAD_BYTES - len(head)]
        tail = (tail + chunk)[-TAIL_BYTES:]
        data = carry + chunk
        whole = len(data) - len(data) % BLOCK_BYTES
        for start in range(0, whole, BLOCK_BYTES):
            block_entropy.append(_count_block(data[start : start + BLOCK_BYTES], histogram))
        carry = data[whole:]
    if carry:
        block_entropy.append(_count_block(carry, histogram))
    hashes = Hashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest(), sha512=sha512.hexdigest())
    return _Scan(size, hashes, histogram, block_entropy, bytes(head), tail)


def _count_block(block: bytes, histogram: list[int]) -> float:
    counts = Counter(block)
    for value, count in counts.items():
        histogram[value] += count
    return shannon_entropy(counts.values(), len(block))


def _entropy_profile(scan: _Scan) -> EntropyProfile:
    span, means = downsample(scan.block_entropy)
    regions = high_entropy_regions(scan.block_entropy, scan.size)
    return EntropyProfile(
        overall=round(shannon_entropy(scan.histogram, scan.size), 4),
        block_size=BLOCK_BYTES,
        block_count=len(scan.block_entropy),
        points_span_blocks=span,
        points=[
            EntropyPoint(offset=index * span * BLOCK_BYTES, entropy=round(mean, 4)) for index, mean in enumerate(means)
        ],
        high_entropy_threshold=HIGH_ENTROPY_BITS,
        high_entropy_regions=regions[:MAX_REGIONS],
        high_entropy_region_count=len(regions),
        high_entropy_bytes=sum(region.end - region.start for region in regions),
    )


def _has_pe_header(head: bytes) -> bool:
    if len(head) < 0x40:
        return False
    offset = int.from_bytes(head[0x3C:0x40], "little")
    return head[offset : offset + 4] == b"PE\x00\x00"


def _zip_kind(head: bytes) -> Kind:
    if b"[Content_Types].xml" not in head:
        return KINDS["zip"]
    for marker, kind_id in _OOXML_PARTS:
        if marker in head:
            return KINDS[kind_id]
    return KINDS["ooxml"]


def _looks_like_text(head: bytes) -> bool:
    try:
        codecs.getincrementaldecoder("utf-8")().decode(head, final=False)  # tolerate a character cut at the end
    except UnicodeDecodeError:
        return False
    return not any(byte < 32 and byte not in _TEXT_CONTROLS for byte in head)


def _finding(finding_id: str, severity: Severity, title: str, explanation: str) -> Finding:
    return Finding(id=finding_id, severity=severity, title=title, explanation=explanation)


def _name_findings(raw_name: str, name: str) -> list[Finding]:
    findings = []
    if any(ch in _BIDI_CONTROLS for ch in raw_name):
        findings.append(
            _finding(
                "bidi_control_in_name",
                "high",
                "File name hides its real extension",
                "The name contains an invisible right-to-left control character, which reverses how the rest of "
                "the name is displayed. It is used to make a program named 'photo[RLO]gpj.exe' appear as "
                f"'photoexe.jpg'. With the control removed, the name is '{name}'.",
            )
        )
    suffixes = [suffix[1:].strip().lower() for suffix in PurePosixPath(name).suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in _RUNNABLE and suffixes[-2] in _DECOY:
        decoy, real = suffixes[-2], suffixes[-1]
        findings.append(
            _finding(
                "double_extension",
                "high",
                f"Name disguises a .{real} file as .{decoy}",
                f"The name ends in .{decoy}.{real}. Windows hides known extensions by default, so this can "
                f"appear as a harmless .{decoy} file while opening it actually runs a .{real} program.",
            )
        )
    return findings


def _type_findings(kind: Kind, extension: str | None, mismatch: bool) -> list[Finding]:
    findings = []
    if kind.id == "empty":
        findings.append(
            _finding("empty_file", "info", "File is empty", "There is no content to analyse beyond the name.")
        )
    if kind.executable:
        findings.append(
            _finding(
                "executable_file",
                "info",
                "File is a program",
                f"The content was identified as {kind.label}. A program can do anything your user account "
                "can, so run it only if you trust where it came from.",
            )
        )
    if mismatch:
        findings.append(
            _finding(
                "extension_mismatch",
                "high" if kind.executable else "medium",
                "Extension does not match the content",
                f"The name ends in .{extension}, but the content was identified as {kind.label}. "
                f"{_DISGUISED if kind.executable else _MISNAMED}",
            )
        )
    return findings


def _content_findings(kind: Kind, extension: str | None, scan: _Scan) -> list[Finding]:
    """Findings from what the content holds: macros, encryption, a hidden program, a script, or a runnable script name."""
    return [
        *_office_findings(kind, extension, scan),
        *_archive_findings(kind, scan.head),
        *_embedded_findings(kind, scan.head),
        *_svg_findings(kind, scan.head),
        *_script_name_findings(kind, extension),
    ]


def _office_findings(kind: Kind, extension: str | None, scan: _Scan) -> list[Finding]:
    if kind.id not in _OFFICE_KINDS or not (_MACRO_PART in scan.head or _MACRO_PART in scan.tail):
        return []
    hidden = extension in _MACRO_FREE
    warning = (
        f"The name ends in .{extension}, an extension that promises no macros, which is a further warning sign."
        if hidden
        else "Many legitimate documents use macros too, so check where it came from before enabling them."
    )
    return [
        _finding(
            "macro_office_file",
            "high" if hidden else "medium",
            "Office document contains macros",
            "The package holds a VBA macro project (vbaProject.bin). Macros are the most common way malicious Office "
            f"documents run code once the reader clicks 'Enable content'. {warning}",
        )
    ]


def _zip_encrypted(head: bytes) -> bool:
    """True when a local file header in the header sample sets the encryption flag (bit 0 of the general flags)."""
    start = 0
    while (at := head.find(b"PK\x03\x04", start)) >= 0 and at + 8 <= len(head):
        if head[at + 6] & 1:
            return True
        start = at + 4
    return False


def _archive_findings(kind: Kind, head: bytes) -> list[Finding]:
    if kind.id != "zip" or not _zip_encrypted(head):
        return []
    return [
        _finding(
            "encrypted_archive",
            "medium",
            "Password-protected archive",
            "At least one file in this ZIP is encrypted, so its contents cannot be inspected. Attackers send "
            "password-protected archives, with the password in the message, so that scanners cannot look inside. "
            "Legitimate archives are sometimes protected too; open it only if you expected it.",
        )
    ]


def _has_embedded_pe(head: bytes) -> bool:
    """True when a PE image starts after offset 0: an MZ header whose e_lfanew points at ``PE\\0\\0``."""
    at = head.find(b"MZ", 1)
    for _ in range(MAX_PE_CANDIDATES):
        if at < 0:
            return False
        if len(head) >= at + 0x40:
            offset = int.from_bytes(head[at + 0x3C : at + 0x40], "little")
            if 0x40 <= offset <= MAX_E_LFANEW and head[at + offset : at + offset + 4] == b"PE\x00\x00":
                return True
        at = head.find(b"MZ", at + 1)
    return False


def _embedded_findings(kind: Kind, head: bytes) -> list[Finding]:
    if kind.id not in _NO_PROGRAM_KINDS or not _has_embedded_pe(head):
        return []
    return [
        _finding(
            "embedded_executable",
            "high",
            "A Windows program is hidden inside this file",
            f"Besides its {kind.label} content, the file holds what looks like a Windows program (a PE image). "
            "Documents and images do not carry programs; attackers append one to a harmless-looking file so that it "
            "passes a type check, and a second stage extracts and runs it.",
        )
    ]


def _svg_findings(kind: Kind, head: bytes) -> list[Finding]:
    if kind.id != "text" or not _SVG.search(head[:4096]) or not _ACTIVE.search(head):
        return []
    return [
        _finding(
            "active_content_svg",
            "medium",
            "Image contains a script",
            "This SVG image holds a <script> element, a javascript: link or an event handler. A browser runs it when "
            "the image is opened on its own, which is how SVG attachments redirect to phishing pages or run code. "
            "Ordinary pictures do not need scripts.",
        )
    ]


def _script_name_findings(kind: Kind, extension: str | None) -> list[Finding]:
    if kind.id not in {"text", "script"} or extension is None:
        return []
    if extension not in _WINDOWS_SCRIPTS and extension != "js":
        return []
    advice = (
        "JavaScript files are also ordinary web content."
        if extension == "js"
        else "Run it only if you wrote it or trust the sender."
    )
    return [
        _finding(
            "runnable_script_file",
            "low" if extension == "js" else "medium",
            f"Script file (.{extension})",
            f"A .{extension} file is a program in text form that Windows can run when it is opened. Malware is "
            f"often sent as a script because mail filters let it through more easily than an .exe. {advice}",
        )
    ]


def _entropy_findings(kind: Kind, entropy: EntropyProfile, size: int) -> list[Finding]:
    random_looking = entropy.overall >= HIGH_ENTROPY_BITS
    regions = entropy.high_entropy_region_count
    if not (random_looking or regions):
        return []
    share = entropy.high_entropy_bytes / size if size else 0.0
    kib = entropy.high_entropy_bytes // 1024
    if kind.compressed:
        return [
            _finding(
                "expected_high_entropy",
                "info",
                "Random-looking data is normal for this format",
                f"This format ({kind.label}) stores compressed data, so high entropy is expected here and is "
                "not suspicious on its own.",
            )
        ]
    if kind.executable and regions:
        return [
            _finding(
                "possible_packing",
                "medium",
                "Program may be packed or contain encrypted code",
                f"{kib:,} KiB ({share:.0%}) of this program looks random. Packers and encrypted payloads look like "
                "this, and malware uses them to hide its code from scanners; installers and programs with "
                "compressed resources can look the same. Treat it with extra care, and use a packer detector or "
                "a sandbox if you need certainty.",
            )
        ]
    if random_looking:
        no_header = " and has no recognised format header" if kind.id == "unknown" else ""
        return [
            _finding(
                "high_entropy_file",
                "medium",
                "Whole file looks encrypted or compressed",
                f"The content looks random ({entropy.overall:.2f} of a possible 8 bits per byte){no_header}. "
                "Encrypted data, such as files locked by ransomware or an encrypted container, and raw "
                "compressed data look like this.",
            )
        ]
    return [
        _finding(
            "high_entropy_region",
            "low",
            "Part of the file looks encrypted or compressed",
            f"{regions} region(s) totalling {kib:,} KiB ({share:.0%}) look random. This can be embedded compressed "
            "data, keys or certificates, or an encrypted payload hidden inside an otherwise ordinary file.",
        )
    ]
