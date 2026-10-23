# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Paths, private writes and the constants every stage shares (standard library only)."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEED = "kestrixcodebench-v1"
SPLITS = ("dev", "test")
TEST_PERCENT = 30
SHARDS = 8
KINDS = ("b", "a", "u")  # before the fix, after the fix, unchanged by the fix
LOCK_NAME = "LOCKED_EVAL.json"
LANGUAGES = ("python", "javascript", "typescript")
EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    # web files (kestrix-scan Phase 1); no other tool reads them, and the original subsets do not include them
    ".vue": "web",
    ".svelte": "web",
    ".html": "web",
    ".htm": "web",
    ".css": "web",
    ".scss": "web",
}
WEB_LANGUAGE = "web"
WEB_EXTENSIONS = tuple(ext for ext, language in EXTENSIONS.items() if language == WEB_LANGUAGE)


class CodeBenchError(RuntimeError):
    """A stage cannot run: missing input, a refused read of the locked test, or inconsistent data."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def seeded_percent(seed: str, value: str) -> int:
    """Stable pseudo-random integer in 0..99 for a seed and a value."""
    return int(hashlib.sha256(f"{seed}\x1f{value}".encode()).hexdigest()[:8], 16) % 100


def ids_sha256(ids: Iterable[str]) -> str:
    return hashlib.sha256("".join(i + "\n" for i in sorted(ids)).encode()).hexdigest()


def shard_of(file_id: str, shards: int = SHARDS) -> int:
    return int(file_id[:6], 16) % shards


def private_dir(path: Path) -> None:
    """Create ``path`` and any missing parents with mode 0700."""
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


class Layout:
    """Where each stage reads and writes under the benchmark root."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def pairs(self) -> Path:
        return self.work / "pairs.jsonl"

    @property
    def unchanged(self) -> Path:
        return self.work / "unchanged.jsonl"

    @property
    def split_manifest(self) -> Path:
        return self.reports / "split-manifest.json"

    @property
    def tools(self) -> Path:
        return self.root / "tools"

    def shard_dir(self, split: str, shard: int) -> Path:
        return self.root / "files" / split / f"shard-{shard:02d}"

    def scan_dir(self, run: str, tool: str) -> Path:
        return self.root / "scans" / run / tool

    def findings_file(self, run: str, tool: str, shard: int) -> Path:
        return self.scan_dir(run, tool) / f"shard-{shard:02d}.findings.jsonl"

    def scan_report(self, run: str, tool: str, shard: int) -> Path:
        return self.scan_dir(run, tool) / f"shard-{shard:02d}.report.json"
