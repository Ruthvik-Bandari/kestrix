# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Feature files and shard reports shared by the link and file benchmarks.

Reading a split's features is ``kestrixmailbench.features.read_features``: the locked test needs a claimed
lock. Each shard report records the code version that produced it, so the locked test can refuse to mix
dev and test features made by different rules.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from kestrixmailbench.features import feature_errors, read_features

from .common import Layout, LinkFileBenchError, write_json, write_jsonl

CODE_ENV = "KESTRIX_GIT_SHA"

__all__ = ["code_versions", "feature_errors", "read_features", "shard_report_path", "write_shard"]


def shard_report_path(layout: Layout, shard: int, splits: tuple[str, ...]) -> Path:
    return layout.reports / f"features-shard-{shard:02d}.{'+'.join(splits)}.json"


def write_shard(
    layout: Layout, shard: int, rows: dict[str, list[dict[str, Any]]], errors: Counter[str]
) -> dict[str, Any]:
    """Write one feature file per split and the shard report (also under the split-specific name)."""
    for side, side_rows in rows.items():
        write_jsonl(layout.feature_file(shard, side), sorted(side_rows, key=lambda r: r["id"]))
    report = {
        "schema_version": 1,
        "shard": shard,
        "splits": list(rows),
        "code": os.environ.get(CODE_ENV),
        "analyzed": {side: len(side_rows) for side, side_rows in rows.items()},
        "errors": dict(sorted(errors.items())),
    }
    write_json(shard_report_path(layout, shard, tuple(rows)), report)
    if "dev" in rows:
        write_json(layout.feature_report(shard), report)
    return report


def code_versions(layout: Layout, split: str) -> set[str | None]:
    """The code versions recorded by the shard reports that analyzed ``split`` (one value when all agree)."""
    versions: set[str | None] = set()
    for shard in range(layout.shards):
        found = False
        for path in sorted(layout.reports.glob(f"features-shard-{shard:02d}.*.json")):
            report = json.loads(path.read_text())
            if split in report["splits"]:
                versions.add(report["code"])
                found = True
        if not found:
            raise LinkFileBenchError(f"no shard report for {split} shard {shard}; run the features job first")
    return versions
