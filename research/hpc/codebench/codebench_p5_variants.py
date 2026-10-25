#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Make leave-one-out scanner trees for the Phase 5 per-change measurement (run on the cluster, login node, light).

``python3 research/hpc/codebench/codebench_p5_variants.py FINAL_TREE OUT_DIR [VARIANT ...]`` copies the synced tree once
per change and switches that one change off by editing the copy; each edit must match
exactly once, so a changed source file fails loudly instead of measuring nothing. Rules that are only dropped need no
tree: ``codebench_p4_ablate.sh`` (with ``PHASE=p5``) filters their findings out of the final run instead.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

RULES = "packages/kestrix-scan/src/kestrix_scan/systems_rules.py"
# Each variant here widens the round-1 scanner (compare r1 against it): the change it would add.
VARIANTS: dict[str, list[tuple[str, str, str]]] = {
    "fmtArgs": [
        (
            RULES,
            "    if len(args) != index + 1:  # a format followed by arguments is usually a deliberate pass-through",
            "    if len(args) <= index:",
        )
    ],
    "copyAny": [(RULES, "    if dest is None or dest not in arrays:", "    if False:")],
}


def main() -> int:
    final, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name in sys.argv[3:] or list(VARIANTS):
        tree = out / name
        if tree.exists():
            shutil.rmtree(tree)
        shutil.copytree(final, tree, ignore=shutil.ignore_patterns("__pycache__"))
        for rel, old, new in VARIANTS[name]:
            path = tree / rel
            text = path.read_text(encoding="utf-8")
            if text.count(old) != 1:
                raise SystemExit(f"{name}: {old!r} matches {text.count(old)} times in {rel}")
            path.write_text(text.replace(old, new), encoding="utf-8")
    print("trees:", ", ".join(sorted(p.name for p in out.iterdir())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
