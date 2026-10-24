#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Make leave-one-out scanner trees for the Phase 2 per-change measurement (run on the cluster, login node, light).

``python3 hpc/codebench_php_variants.py FINAL_TREE OUT_DIR [VARIANT ...]`` copies the synced tree once per change and switches that one
change off by editing the copy; each edit is asserted to match exactly once, so a changed source file fails loudly
instead of measuring nothing. Scan a tree with ``scan --tool kestrix@NAME --kestrix-tree NAME=OUT_DIR/NAME``.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SCAN = "packages/kestrix-scan/src/kestrix_scan"
BUILT = 'BUILT_TIER = frozenset({"php.sql.injection", "php.exec.eval", "php.exec.command"})'
# change id -> list of (file, old text, new text)
VARIANTS: dict[str, list[tuple[str, str, str]]] = {
    "noBuilt": [(f"{SCAN}/php_rules.py", BUILT, "BUILT_TIER: frozenset[str] = frozenset()")],
    "noBuiltSql": [(f"{SCAN}/php_rules.py", BUILT, 'BUILT_TIER = frozenset({"php.exec.eval", "php.exec.command"})')],
    "noBuiltExec": [(f"{SCAN}/php_rules.py", BUILT, 'BUILT_TIER = frozenset({"php.sql.injection", "php.exec.eval"})')],
    "noFollow": [(f"{SCAN}/php_rules.py", "BUILT_FOLLOW = True", "BUILT_FOLLOW = False")],
    "noParams": [(f"{SCAN}/php_rules.py", "BUILT_PARAMS = True", "BUILT_PARAMS = False")],
    "noIdent": [(f"{SCAN}/php_rules.py", "BUILT_IDENTIFIERS = True", "BUILT_IDENTIFIERS = False")],
    "tightA": [  # bindings followed, parameters and identifier-like names left out
        (f"{SCAN}/php_rules.py", "BUILT_PARAMS = True", "BUILT_PARAMS = False"),
        (f"{SCAN}/php_rules.py", "BUILT_IDENTIFIERS = True", "BUILT_IDENTIFIERS = False"),
    ],
    "tightB": [  # parameters followed, bindings and identifier-like names left out
        (f"{SCAN}/php_rules.py", "BUILT_FOLLOW = True", "BUILT_FOLLOW = False"),
        (f"{SCAN}/php_rules.py", "BUILT_IDENTIFIERS = True", "BUILT_IDENTIFIERS = False"),
    ],
    "tightC": [
        (f"{SCAN}/php_rules.py", "BUILT_FOLLOW = True", "BUILT_FOLLOW = False"),
        (f"{SCAN}/php_rules.py", "BUILT_PARAMS = True", "BUILT_PARAMS = False"),
        (f"{SCAN}/php_rules.py", "BUILT_IDENTIFIERS = True", "BUILT_IDENTIFIERS = False"),
    ],
    "noBuiltEval": [
        (f"{SCAN}/php_rules.py", BUILT, 'BUILT_TIER = frozenset({"php.sql.injection", "php.exec.command"})')
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
