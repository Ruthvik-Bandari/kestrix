#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Make leave-one-out scanner trees for the Phase 4 per-change measurement (run on the cluster, login node, light).

``python3 research/hpc/codebench/codebench_p4_variants.py FINAL_TREE OUT_DIR [VARIANT ...]`` copies the synced tree once
per change and switches that one change off (or, for ``wideParams``, on) by editing the copy; each edit must match
exactly once, so a changed source file fails loudly instead of measuring nothing. Rules that are only dropped need no
tree: ``codebench_p4_ablate.sh`` filters their findings out of the final run instead.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

RULES = "packages/kestrix-scan/src/kestrix_scan/server_rules.py"
INDEX = "packages/kestrix-scan/src/kestrix_scan/server_index.py"
VARIANTS: dict[str, list[tuple[str, str, str]]] = {
    "noBuilt": [(RULES, "        if dynamic and (raw or _SQL.search(text)):", "        if False:")],
    "noFollow": [(RULES, "_BUILT_FOLLOW = True", "_BUILT_FOLLOW = False")],
    "wideParams": [(RULES, "_BUILT_PARAMS = False", "_BUILT_PARAMS = True")],
    "noLowXss": [
        (RULES, "        if not c.literal(lo, hi) and not c._literal_value(lo, hi, 0):", "        if False:"),
        (
            RULES,
            "            if not c.literal(lo, i - 1) and not c._literal_value(lo, i - 1, 0) and c.toks[lo].kind != STR:",
            "            if False:",
        ),
        (RULES, ") and not c.literal(*args[0]):", ") and False:"),
        (
            RULES,
            "        tainted = bool(_ERB_REQUEST.search(expr))\n",
            "        tainted = bool(_ERB_REQUEST.search(expr))\n        if not tainted:\n            continue\n",
        ),
    ],
    "noGoWrite": [
        (
            RULES,
            '    elif qualified in ("fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln", "io.WriteString") and len(args) >= 2:',
            "    elif False:",
        ),
        (
            RULES,
            '    elif word == "Write" and len(names) == 2 and _is_writer(c, (i - 2, i - 1)) and args:',
            "    elif False:",
        ),
    ],
    "noUpload": [
        (INDEX, "            member in _UPLOAD_MEMBERS and _UPLOAD.search(name)", "            False"),
        (INDEX, "        if (_ARCHIVE_ENTRY.match(name) and member in _ARCHIVE_MEMBERS) or (", "        if False or ("),
    ],
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
