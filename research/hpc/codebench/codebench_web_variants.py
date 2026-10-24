#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Make leave-one-out scanner trees for the Phase 1 per-change measurement (run on the cluster, login node, light).

``python3 research/hpc/codebench/codebench_web_variants.py FINAL_TREE OUT_DIR`` copies the synced final tree once per change and switches
that one change off by editing a constant or a condition in the copy (each edit is asserted to match exactly once, so
a changed source file fails loudly instead of measuring nothing). ``base`` is the final tree with the scanner of the
commit the phase started from (``BASE_SRC``, a directory holding that commit's ``kestrix_scan``). The measurement is
leave-one-out: final against final-without-the-change.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SCAN = "packages/kestrix-scan/src/kestrix_scan"
# change id -> list of (file, old text, new text)
VARIANTS: dict[str, list[tuple[str, str, str]]] = {
    "noNextCtx": [(f"{SCAN}/js_rules.py", "next_context = bool(", "next_context = False and bool(")],
    "noNextRedirect": [(f"{SCAN}/js_rules.py", "_NEXT_REDIRECTS = {", "_NEXT_REDIRECTS: dict[str, str] = {} and {")],
    "noNest": [(f"{SCAN}/js_index.py", "_NEST_SOURCES = {", "_NEST_SOURCES: dict[str, str] = {} and {")],
    "noKoa": [
        (f"{SCAN}/js_index.py", 'if names[1] == "get" and len(segs) >= 3 and segs[2].kind == "call":', "if False:"),
        (f"{SCAN}/js_index.py", '"url", "originalUrl", "path", "headers"})', '"url", "originalUrl", "path"})'),
        (f"{SCAN}/js_index.py", '"url", "path", "files", "headers")', '"url", "path", "files")'),
    ],
    "noBody": [(f"{SCAN}/js_index.py", "_BODY_READERS = frozenset({", "_BODY_READERS = frozenset() and frozenset({")],
    "noUrl2": [
        (
            f"{SCAN}/js_index.py",
            'if name == "URL" and len(args) >= 2:',
            'if name == "URL" and len(args) >= 2 and False:',
        )
    ],
    "noAngular": [
        (
            f"{SCAN}/js_rules.py",
            '            last.startswith("bypassSecurityTrust")\n',
            '            False\n            and last.startswith("bypassSecurityTrust")\n',
        )
    ],
}


def main() -> int:
    final, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, edits in VARIANTS.items():
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
    base_src = sys.argv[3] if len(sys.argv) > 3 else None
    if base_src:
        tree = out / "base"
        if tree.exists():
            shutil.rmtree(tree)
        shutil.copytree(final, tree, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.rmtree(tree / SCAN)
        shutil.copytree(base_src, tree / SCAN, ignore=shutil.ignore_patterns("__pycache__"))
    print("trees:", ", ".join(sorted(p.name for p in out.iterdir())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
