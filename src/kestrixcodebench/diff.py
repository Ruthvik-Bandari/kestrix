# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Changed line ranges between the before and after version of a file, and the line mapping between them.

A file pair is diffed once with ``difflib`` (``autojunk`` off, so blank lines do not break the alignment). Only the
non-equal opcodes are stored, as ``[i1, i2, j1, j2]`` (0-based, half-open, old then new side). From them:

* ``old_ranges``: the before-file lines a fix touched, as 1-based inclusive ranges; a pure insertion counts as the two
  lines around the insertion point, because a fix that only adds a check belongs to the line it guards;
* ``map_old_line``: where a before-file line is in the after-file (a window when the line itself changed).
"""

from __future__ import annotations

import difflib

Op = tuple[int, int, int, int]
MAX_LINES = 20_000


def diff_ops(before: str, after: str) -> list[Op]:
    """Non-equal opcodes between the lines of ``before`` and ``after``."""
    a, b = before.splitlines(), after.splitlines()
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [(i1, i2, j1, j2) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal"]


def old_ranges(ops: list[Op], old_lines: int) -> list[tuple[int, int]]:
    """Before-file lines touched by the ops, 1-based inclusive."""
    out: list[tuple[int, int]] = []
    for i1, i2, _, _ in ops:
        if i2 > i1:
            out.append((i1 + 1, i2))
        elif old_lines:
            out.append((max(1, i1), min(old_lines, i1 + 1)))
    return out


def map_old_line(ops: list[Op], line: int) -> tuple[int, int]:
    """The after-file lines (inclusive window) that a before-file line corresponds to."""
    shift = 0
    index = line - 1
    for i1, i2, j1, j2 in ops:
        if index < i1:
            break
        if index < i2:
            return (j1 + 1, j2) if j2 > j1 else (max(1, j1), j1 + 1)
        shift = j2 - i2
    mapped = index + shift + 1
    return mapped, mapped


def near(ranges: list[tuple[int, int]], line: int, end_line: int, margin: int) -> bool:
    """Whether the finding's lines come within ``margin`` lines of any range."""
    return any(line <= hi + margin and end_line >= lo - margin for lo, hi in ranges)
