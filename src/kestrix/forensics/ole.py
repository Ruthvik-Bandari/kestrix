# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only look at the directory of an OLE2 / Compound File (legacy .doc, .xls, .ppt).

Only the header, the FAT sectors that the directory chain needs and the directory sectors themselves are read:
nothing is decoded, decompressed or executed, and every loop is bounded, so a hostile or damaged file costs a few
hundred small reads at most. The result says whether the directory holds a VBA macro project; a file that cannot
be read as a compound file gives ``readable=False`` and no claim either way.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
HEADER_BYTES = 512
MAX_FAT_SECTORS = 1024  # FAT sectors consulted (a 512-byte sector maps 128 sectors, so 8 MiB of file per 64)
MAX_DIFAT_SECTORS = 64
MAX_DIRECTORY_SECTORS = 256
MAX_ENTRIES = 4096
ENTRY_BYTES = 128
MAX_REGULAR_SECTOR = 0xFFFFFFFA
STORAGE, STREAM = 1, 2
# Entry names that mark a VBA project: the project storage, its signature stream and the Word and Excel containers.
_VBA_STORAGES = frozenset({"VBA", "Macros", "_VBA_PROJECT_CUR"})
_VBA_STREAMS = frozenset({"_VBA_PROJECT"})


@dataclass(frozen=True)
class OleResult:
    readable: bool
    has_vba: bool = False
    names: frozenset[str] = field(default_factory=frozenset)
    note: str = ""


class _Unreadable(Exception):
    """The structure cannot be followed; the message becomes the note."""


class _Compound:
    """Sector reads over a compound file, every one bounds-checked against the file size."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        stream.seek(0)
        header = stream.read(HEADER_BYTES)
        if len(header) < HEADER_BYTES or header[:8] != MAGIC:
            raise _Unreadable("not a compound file header")
        (shift,) = struct.unpack_from("<H", header, 0x1E)
        if shift not in (9, 12):
            raise _Unreadable("unsupported sector size")
        self.stream = stream
        self.sector = 1 << shift
        self.count = max(0, size // self.sector - 1)
        (self.first_dir,) = struct.unpack_from("<I", header, 0x30)
        self.fat_ids = self._fat_ids(header)
        self.fat_cache: dict[int, tuple[int, ...] | None] = {}

    def read(self, index: int) -> bytes | None:
        if index > MAX_REGULAR_SECTOR or index >= self.count:
            return None
        self.stream.seek(self.sector * (index + 1))
        data = self.stream.read(self.sector)
        return data if len(data) == self.sector else None

    def _fat_ids(self, header: bytes) -> list[int]:
        ids = [v for v in struct.unpack_from("<109I", header, 0x4C) if v <= MAX_REGULAR_SECTOR]
        start, count = struct.unpack_from("<II", header, 0x44)
        seen: set[int] = set()
        for _ in range(min(count, MAX_DIFAT_SECTORS)):
            if start > MAX_REGULAR_SECTOR or start in seen:
                break
            seen.add(start)
            data = self.read(start)
            if data is None:
                raise _Unreadable("extended FAT table runs past the end of the file")
            entries = struct.unpack_from(f"<{self.sector // 4}I", data)
            ids += [v for v in entries[:-1] if v <= MAX_REGULAR_SECTOR]
            start = entries[-1]
        return ids[:MAX_FAT_SECTORS]

    def next(self, index: int) -> int:
        which, offset = divmod(index, self.sector // 4)
        if which >= len(self.fat_ids):
            raise _Unreadable("directory chain leaves the FAT")
        if which not in self.fat_cache:
            data = self.read(self.fat_ids[which])
            self.fat_cache[which] = struct.unpack_from(f"<{self.sector // 4}I", data) if data else None
        table = self.fat_cache[which]
        if table is None:
            raise _Unreadable("FAT sector lies outside the file")
        return int(table[offset])

    def directory(self) -> bytes:
        out = bytearray()
        seen: set[int] = set()
        current = self.first_dir
        while current <= MAX_REGULAR_SECTOR and len(seen) < MAX_DIRECTORY_SECTORS:
            if current in seen:
                raise _Unreadable("directory chain loops")
            seen.add(current)
            data = self.read(current)
            if data is None:
                raise _Unreadable("directory sector lies outside the file")
            out += data
            current = self.next(current)
        if not out:
            raise _Unreadable("no directory")
        return bytes(out)


def _entries(directory: bytes) -> list[tuple[int, str]]:
    """(type, name) of each storage and stream entry, at most ``MAX_ENTRIES``."""
    found = []
    for at in range(0, min(len(directory), MAX_ENTRIES * ENTRY_BYTES) - ENTRY_BYTES + 1, ENTRY_BYTES):
        entry = directory[at : at + ENTRY_BYTES]
        (name_len,) = struct.unpack_from("<H", entry, 64)
        if entry[66] in (STORAGE, STREAM) and 2 <= name_len <= 64 and name_len % 2 == 0:
            found.append((entry[66], entry[: name_len - 2].decode("utf-16-le", "replace")))
    return found


def parse_ole_directory(stream: BinaryIO, size: int) -> OleResult:
    """Read the directory of the compound file in ``stream`` (``size`` bytes) and look for a VBA project."""
    try:
        entries = _entries(_Compound(stream, size).directory())
    except _Unreadable as exc:
        return OleResult(False, note=str(exc))
    names = frozenset(name for _, name in entries)
    has_vba = (
        any(
            (kind == STORAGE and name in _VBA_STORAGES) or (kind == STREAM and name in _VBA_STREAMS)
            for kind, name in entries
        )
        or {"PROJECT", "PROJECTwm"} <= names
    )  # the description streams a VBA project always writes
    return OleResult(True, has_vba, names)
