# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""List dev pairs a tool missed in one family, for hand analysis of a rule gap on the cluster.

Prints ids, repository, file path, CWEs, changed line ranges and the rules that fired near the change; never code.
Dev only: the locked test is never listed.
"""

from __future__ import annotations

from .common import SHARDS, Layout, read_jsonl
from .diff import near
from .metrics import MARGIN, read_findings


def list_examples(layout: Layout, tool: str, run: str, family: str, count: int) -> list[str]:
    findings = read_findings(layout, run, tool, SHARDS)
    lines = []
    for row in read_jsonl(layout.pairs):
        if row["split"] != "dev" or family not in row["families"]:
            continue
        ranges = [(lo, hi) for lo, hi in row["old_ranges"]]
        found = findings.get(("b", row["id"]), [])
        if any(family in fams and near(ranges, line, end, MARGIN) for _, line, end, fams in found):
            continue
        rules = sorted({r for r, line, end, _ in found if near(ranges, line, end, MARGIN)})
        lines.append(
            f"{row['id']} {row['repos'][0]} {row['path']} cwes={row['cwes']} changed={row['old_ranges'][:4]} near_rules={rules}"
        )
    return lines[:count]
