#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Make leave-one-out scanner trees for the Phase 2 per-change measurement (run on the cluster, login node, light).

``python3 research/hpc/codebench/codebench_php_variants.py FINAL_TREE OUT_DIR [VARIANT ...]`` copies the synced tree once per change and switches that one
change off by editing the copy; each edit is asserted to match exactly once, so a changed source file fails loudly
instead of measuring nothing. Scan a tree with ``scan --tool kestrix@NAME --kestrix-tree NAME=OUT_DIR/NAME``.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SCAN = "packages/kestrix-scan/src/kestrix_scan"
# change id -> list of (file, old text, new text)
VARIANTS: dict[str, list[tuple[str, str, str]]] = {
    "noBuiltSql": [
        (
            f"{SCAN}/php_rules.py",
            "if (raw or sql_text) and self._built(lo, hi, tight=True)[0]:",
            "if False and (raw or sql_text) and self._built(lo, hi, tight=True)[0]:",
        )
    ],
}


def main() -> int:
    final, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    wanted = sys.argv[3:] or list(VARIANTS)
    for name in wanted:
        edits = VARIANTS[name]
        tree = out / name
        if tree.exists():
            shutil.rmtree(tree)
        shutil.copytree(final, tree, ignore=shutil.ignore_patterns("__pycache__"))
        for rel, old, new in edits:
            path = tree / rel
            text = path.read_text(encoding="utf-8")
            if text.count(old) != 1:
                raise SystemExit(f"{name}: {old!r} matches {text.count(old)} times in {rel}")
            path.write_text(text.replace(old, new), encoding="utf-8")
    print("trees:", ", ".join(sorted(p.name for p in out.iterdir())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
