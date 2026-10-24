# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Scan speed on every ``STRIDE``-th file of the fetched corpus (as a directory scan would read it): ``scan_text`` per file, best of 2.

Run once per scanner source tree: ``PYTHONPATH=<src> python3 iac_speed.py CORPUS [STRIDE]``. It prints files per second and the finding count.
"""

import sys
import time
from pathlib import Path

from kestrix_scan.analyze import scan_text
from kestrix_scan.walk import Candidate

root = Path(sys.argv[1])
stride = int(sys.argv[2]) if len(sys.argv) > 2 else 1
files = [p for p in sorted(root.rglob("*")) if p.is_file()][::stride]
texts = []
for path in files:
    try:
        texts.append(
            (
                path,
                path.relative_to(root).as_posix().split("/", 1)[-1],
                path.read_bytes()[:1_048_576].decode("utf-8", "replace"),
            )
        )
    except OSError:
        continue
best = float("inf")
count = 0
for _ in range(2):
    started = time.perf_counter()
    count = 0
    for path, rel, text in texts:
        count += len(scan_text(text, Candidate(path=path, rel=rel))[0])
    best = min(best, time.perf_counter() - started)
print(f"files={len(texts)} findings={count} seconds={best:.1f} files_per_second={len(texts) / best:.1f}")
