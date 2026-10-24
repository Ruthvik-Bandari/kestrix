#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Derive a kestrix run from another by dropping the findings of some rules (cluster side, login node, light).

``python3 research/hpc/codebench/codebench_derive.py ROOT SOURCE_RUN NEW_RUN RULE [RULE ...]`` copies ``SOURCE_RUN``'s findings and scan
reports to ``NEW_RUN``, leaving out every finding whose rule id is one of the RULEs. A new rule that has its own rule
id and does not change any other rule's findings is measured alone this way: scan the final scanner once, drop the
other new rules, and compare against the baseline run. A rule that widens an existing rule's id needs a tree of its
own instead (``research/hpc/codebench/codebench_web_variants.py``).
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def derive(root: Path, source: str, new: str, drop: frozenset[str]) -> dict[str, int]:
    src, dst = root / "scans" / source / "kestrix", root / "scans" / new / "kestrix"
    dst.mkdir(parents=True, exist_ok=True, mode=0o700)
    dropped: dict[str, int] = {}
    for path in sorted(src.glob("shard-*.findings.jsonl")):
        kept = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rule = json.loads(line)["r"]
            if rule in drop:
                dropped[rule] = dropped.get(rule, 0) + 1
            else:
                kept.append(line)
        (dst / path.name).write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")
        report = path.with_name(path.name.replace(".findings.jsonl", ".report.json"))
        shutil.copyfile(report, dst / report.name)
    return dropped


def main() -> int:
    if len(sys.argv) < 5:
        raise SystemExit("usage: codebench_derive.py ROOT SOURCE_RUN NEW_RUN RULE [RULE ...]")
    root, source, new, *rules = sys.argv[1:]
    print(json.dumps(derive(Path(root), source, new, frozenset(rules)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
