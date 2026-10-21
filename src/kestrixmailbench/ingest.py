# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Read raw messages out of mbox files and tar archives without extracting anything to disk."""

from __future__ import annotations

import tarfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .common import seeded_key

# Mirrors kestrix.mail.parse.MAX_MESSAGE_BYTES (25 MiB); a larger member is dropped, never read.
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
TOO_LARGE = "input_too_large"


@dataclass(frozen=True)
class RawMessage:
    origin: str
    data: bytes
    # Set instead of ``data`` when the member was skipped before reading.
    skip: str | None = None
    rank: str = ""


def split_mbox(fh: BinaryIO) -> Iterator[bytes]:
    """Split an mbox stream at ``From `` separator lines that follow a blank line (or start the file).

    The separator is dropped and the blank line before the next one is trimmed. Text that merely looks
    like a separator would split a message in two; the fragment then fails the header check later.
    """
    chunk: list[bytes] = []
    blank = True
    for line in fh:
        if blank and line.startswith(b"From ") and len(line.split()) >= 2:
            if chunk:
                yield _join(chunk)
            chunk = []
            blank = False
            continue
        chunk.append(line)
        blank = line in (b"\n", b"\r\n")
    if chunk:
        yield _join(chunk)


def _join(chunk: list[bytes]) -> bytes:
    if chunk and chunk[-1] in (b"\n", b"\r\n"):
        chunk = chunk[:-1]
    return b"".join(chunk)


def iter_mbox(path: Path, limit: int | None = None) -> Iterator[RawMessage]:
    with path.open("rb") as fh:
        for n, data in enumerate(split_mbox(fh)):
            if limit is not None and n >= limit:
                return
            if len(data) > MAX_MESSAGE_BYTES:
                yield RawMessage(path.name, b"", skip=TOO_LARGE)
            elif data.strip():
                yield RawMessage(path.name, data)


def iter_tar_messages(path: Path, limit: int | None = None) -> Iterator[RawMessage]:
    """One message per regular file of a tar archive (SpamAssassin layout); ``cmds`` index files are skipped."""
    origin = path.name.split(".tar", 1)[0]
    taken = 0
    with tarfile.open(path, mode="r|*") as archive:
        for member in archive:
            if not member.isfile() or member.name.rsplit("/", 1)[-1] == "cmds":
                continue
            if limit is not None and taken >= limit:
                return
            taken += 1
            if member.size > MAX_MESSAGE_BYTES:
                yield RawMessage(origin, b"", skip=TOO_LARGE)
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                yield RawMessage(origin, handle.read())


def enron_names(path: Path) -> list[str]:
    """Names of every regular file in the Enron archive (first streaming pass)."""
    with tarfile.open(path, mode="r|gz") as archive:
        return [m.name for m in archive if m.isfile()]


def enron_select(names: list[str], count: int, seed: str) -> dict[str, str]:
    """The ``count`` names with the smallest seeded hash, as {name: rank key}."""
    ranked = sorted((seeded_key(seed, name), name) for name in names)[:count]
    return {name: key for key, name in ranked}


def enron_user(name: str) -> str:
    parts = name.split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "maildir" else "unknown"


def iter_enron(path: Path, selected: dict[str, str]) -> Iterator[RawMessage]:
    """Read only the selected members (second streaming pass); ``rank`` carries the sampling order."""
    remaining = set(selected)
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            if member.name not in remaining:
                continue
            remaining.discard(member.name)
            if member.size > MAX_MESSAGE_BYTES:
                yield RawMessage(enron_user(member.name), b"", skip=TOO_LARGE, rank=selected[member.name])
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                yield RawMessage(enron_user(member.name), handle.read(), rank=selected[member.name])
            if not remaining:
                return
