# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Paths, private file writes, JSON lines and the constants shared by every stage (standard library only)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

SEED = "kestrixmail-v1"
SHARDS = 16
LABELS = ("ham", "phishing", "spam")
POSITIVE_LABELS = ("phishing", "spam")
SPLITS = ("dev", "test")
TEST_FRACTION = 0.3
MIN_YEAR = 1990
MAX_YEAR = 2026
LOCK_NAME = "LOCKED_EVAL.json"
SYNTHETIC = "synthetic"


class MailBenchError(RuntimeError):
    """A stage cannot run: missing input, a refused read of the locked test, or inconsistent data."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def seeded_key(seed: str, value: str) -> str:
    """Stable pseudo-random sort key: hex SHA-256 of the seed and the value."""
    return hashlib.sha256(f"{seed}\x1f{value}".encode()).hexdigest()


def ids_sha256(ids: Iterable[str]) -> str:
    return hashlib.sha256("".join(i + "\n" for i in sorted(ids)).encode()).hexdigest()


def private_dir(path: Path) -> None:
    """Create ``path`` and any missing parents with mode 0700 (``mkdir(parents=True)`` would not for the parents)."""
    missing = [p for p in (path, *path.parents) if not p.exists()]
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)


def write_private(path: Path, data: bytes) -> None:
    """Atomic write, directories 0700 and the file 0600."""
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def write_json(path: Path, obj: object) -> None:
    write_private(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_private(path, b"".join((json.dumps(r, sort_keys=True) + "\n").encode() for r in rows))


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row: dict[str, Any] = json.loads(line)
                yield row


def message_year(data: bytes) -> int | None:
    """Year of the Date header when it parses to a plausible year, else None."""
    try:
        head = data[:65536]
        value = BytesHeaderParser().parsebytes(head).get("Date")
        if not value:
            return None
        year = parsedate_to_datetime(str(value)).year
    except (TypeError, ValueError, IndexError, OverflowError, AttributeError, LookupError):
        return None
    return year if MIN_YEAR <= year <= MAX_YEAR else None


_NON_WORD = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    return _NON_WORD.sub("-", text.lower()).strip("-")


class Layout:
    """Where each stage reads and writes under the benchmark root."""

    def __init__(self, root: Path, shards: int = SHARDS) -> None:
        self.root = root
        self.shards = shards

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def manifests(self) -> Path:
        return self.root / "manifests"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def features(self) -> Path:
        return self.root / "features"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    def raw_shard(self, shard: int) -> Path:
        return self.work / "raw" / f"shard-{shard:02d}.jsonl"

    @property
    def meta(self) -> Path:
        return self.work / "meta.jsonl"

    @property
    def split(self) -> Path:
        return self.work / "split.jsonl"

    @property
    def split_manifest(self) -> Path:
        return self.reports / "split-manifest.json"

    def feature_file(self, shard: int, split: str) -> Path:
        return self.features / f"shard-{shard:02d}.{split}.jsonl"

    def feature_report(self, shard: int) -> Path:
        return self.reports / f"features-shard-{shard:02d}.json"
