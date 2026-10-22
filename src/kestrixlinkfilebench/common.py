# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Constants and path helpers of the link and file benchmark; shared plumbing comes from ``kestrixmailbench``."""

from __future__ import annotations

from pathlib import Path

from kestrixmailbench.common import (
    LOCK_NAME,
    SYNTHETIC,
    Layout,
    MailBenchError,
    file_sha256,
    ids_sha256,
    now,
    private_dir,
    read_jsonl,
    seeded_key,
    write_json,
    write_jsonl,
    write_private,
)

# One error type for the whole family, so a single handler in the CLI catches reads of mail-style layouts too.
LinkFileBenchError = MailBenchError

SEED = "kestrixlinkfile-v1"
TEST_FRACTION = 0.3
SPLITS = ("dev", "test")
KINDS = ("link", "file")
DEFAULT_SHARDS = {"link": 16, "file": 20}
PHISHING = "phishing"
BENIGN = "benign"
LABELS = (PHISHING, BENIGN)


def kind_layout(root: Path, kind: str, shards: int | None = None) -> Layout:
    """Layout of one benchmark (``link`` or ``file``) under ``root``; the raw downloads stay in ``root/raw``."""
    if kind not in KINDS:
        raise LinkFileBenchError(f"unknown benchmark kind {kind!r}")
    return Layout(root / kind, shards or DEFAULT_SHARDS[kind])


__all__ = [
    "BENIGN",
    "DEFAULT_SHARDS",
    "KINDS",
    "LABELS",
    "LOCK_NAME",
    "PHISHING",
    "SEED",
    "SPLITS",
    "SYNTHETIC",
    "TEST_FRACTION",
    "Layout",
    "LinkFileBenchError",
    "file_sha256",
    "ids_sha256",
    "kind_layout",
    "now",
    "private_dir",
    "read_jsonl",
    "seeded_key",
    "write_json",
    "write_jsonl",
    "write_private",
]
