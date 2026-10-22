# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Line diffs, the line mapping between versions, and the CWE families."""

from kestrixcodebench.diff import diff_ops, map_old_line, near, old_ranges
from kestrixcodebench.families import (
    bandit_families,
    eslint_families,
    families_for_cwes,
    kestrix_families,
    parse_cwes,
)

BEFORE = "a\nb\nc\nd\ne\nf\ng\nh\n"
AFTER = "a\nb\nC1\nC2\nd\ne\nf\ng\nh\n"  # line 3 replaced by two lines


def test_replacement_gives_old_range_and_window():
    ops = diff_ops(BEFORE, AFTER)
    assert ops == [(2, 3, 2, 4)]
    assert old_ranges(ops, 9) == [(3, 3)]
    assert map_old_line(ops, 3) == (3, 4)  # the changed line maps to the whole new block
    assert map_old_line(ops, 1) == (1, 1)
    assert map_old_line(ops, 5) == (6, 6)  # shifted by the extra line


def test_pure_insertion_counts_as_the_lines_around_it():
    ops = diff_ops("a\nb\nc\n", "a\nb\nguard\nc\n")
    assert ops == [(2, 2, 2, 3)]
    assert old_ranges(ops, 4) == [(2, 3)]
    assert map_old_line(ops, 3) == (4, 4)


def test_pure_deletion_maps_to_the_gap():
    ops = diff_ops("a\nb\nc\n", "a\nc\n")
    assert old_ranges(ops, 4) == [(2, 2)]
    assert map_old_line(ops, 2) == (1, 2)  # the lines around the gap


def test_near_uses_overlap_and_margin():
    ranges = [(10, 12)]
    assert near(ranges, 15, 15, 3)
    assert near(ranges, 7, 7, 3)
    assert not near(ranges, 16, 16, 3)
    assert not near(ranges, 6, 6, 3)
    assert near(ranges, 1, 8, 3)  # a multi-line finding that reaches into the margin


def test_parse_cwes_drops_placeholders_and_normalizes():
    assert parse_cwes(["CWE-079", "NVD-CWE-Other", "CWE-79", "cwe-22"]) == [79, 22]


def test_families():
    assert families_for_cwes([79, 20, 1321]) == {"xss", "protopollution"}
    assert kestrix_families("py.os.system", "CWE-78") == {"cmdi"}
    assert kestrix_families("js.dom.xss_sink", "CWE-79") == {"xss"}
    assert kestrix_families("py.llm.output_to_sink", "CWE-89") == {"sqli"}
    assert kestrix_families("secret.generic", "CWE-798") == {"secrets"}
    assert kestrix_families("dep.vulnerable", "CWE-1395") == frozenset()
    assert bandit_families("B307", 78) == {"codeinj"}  # override beats the CWE Bandit reports
    assert bandit_families("B608", 89) == {"sqli"}
    assert bandit_families("B101", None) == frozenset()
    assert eslint_families("security/detect-child-process") == {"cmdi"}
    assert eslint_families("security/detect-new-buffer") == frozenset()
