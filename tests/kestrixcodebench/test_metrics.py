# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Pair evaluation, fix-aware detection and the grouped bootstrap on hand-made findings."""

from typing import Any

import numpy as np

from kestrixcodebench.diff import diff_ops, old_ranges
from kestrixcodebench.metrics import Frame, evaluate_pair, evaluate_tool, metrics_for, overlap


def pair(
    file_id: str, repo: str, families: list[str], before: str, after: str, language: str = "python", commit: str = "c"
) -> dict[str, Any]:
    ops = diff_ops(before, after)
    lines = before.count("\n") + 1
    return {
        "id": file_id,
        "repos": [repo],
        "commits": [commit],
        "families": families,
        "language": language,
        "before_lines": lines,
        "after_lines": after.count("\n") + 1,
        "ops": [list(o) for o in ops],
        "old_ranges": [list(r) for r in old_ranges(ops, lines)],
    }


CODE = "\n".join(f"line{i}" for i in range(1, 41)) + "\n"
FIXED = CODE.replace("line20", "safe20")


def test_detection_needs_family_and_nearness():
    row = pair("p1", "o/r", ["cmdi"], CODE, FIXED)
    near_hit = evaluate_pair(row, [("py.os.system", 21, 21, ("cmdi",))], [])
    assert near_hit.matched == {"cmdi"} and near_hit.fixed == {"cmdi"} and near_hit.tp_findings == 1
    wrong_family = evaluate_pair(row, [("py.sql", 20, 20, ("sqli",))], [])
    assert not wrong_family.matched and wrong_family.any_near
    far = evaluate_pair(row, [("py.os.system", 30, 30, ("cmdi",))], [])
    assert not far.matched and not far.any_near


def test_fix_aware_requires_the_finding_to_disappear():
    row = pair("p1", "o/r", ["cmdi"], CODE, FIXED)
    before = [("py.os.system", 20, 20, ("cmdi",))]
    persists = evaluate_pair(row, before, [("py.os.system", 20, 20, ("cmdi",))])
    assert persists.matched == {"cmdi"} and not persists.fixed
    other_rule = evaluate_pair(row, before, [("py.subprocess.shell_true", 20, 20, ("cmdi",))])
    assert other_rule.fixed == {"cmdi"}  # a different rule is not the same finding
    assert evaluate_pair(row, before, []).after_alerts == 0


def test_persisting_finding_is_followed_through_a_shift():
    shifted = "guard1\nguard2\n" + CODE
    row = pair("p1", "o/r", ["cmdi"], CODE, shifted.replace("line20", "safe20"))
    before = [("py.os.system", 20, 20, ("cmdi",))]
    after_same_place = [("py.os.system", 22, 22, ("cmdi",))]  # moved down two lines, still there
    assert not evaluate_pair(row, before, after_same_place).fixed


def frame_and_findings() -> tuple[Frame, dict[tuple[str, str], list[Any]]]:
    pairs = [
        pair("p1", "o/a", ["cmdi"], CODE, FIXED),
        pair("p2", "o/a", ["xss"], CODE, FIXED, "javascript"),
        pair("p3", "o/b", [], CODE, FIXED),  # CVE without a mapped CWE: not in scope
        pair("p4", "o/c", ["cmdi"], CODE, FIXED),
    ]
    unchanged = [{"id": "u1", "repo": "o/b", "language": "python", "lines": 100}]
    findings = {
        ("b", "p1"): [("py.os.system", 20, 20, ("cmdi",))],
        ("a", "p1"): [("py.hash", 1, 1, ("hash",))],
        ("b", "p3"): [("py.os.system", 20, 20, ("cmdi",))],
        ("u", "u1"): [("py.hash", 1, 1, ("hash",)), ("py.hash", 9, 9, ("hash",))],
    }
    return Frame(pairs, unchanged, reps=200, seed=1), findings


def test_headline_metrics():
    frame, findings = frame_and_findings()
    ev = evaluate_tool(frame, "t", findings)
    m = metrics_for(frame, ev, ("python", "javascript"))
    assert (m["pairs"], m["pairs_in_scope"], m["unchanged_files"]) == (4, 3, 1)
    assert m["detection"]["k"] == 1 and m["detection"]["n"] == 3
    assert m["fix_aware_detection"]["k"] == 1
    assert m["any_finding_near_change"]["k"] == 2  # p1 and the out-of-scope p3
    assert m["false_alarms_per_kloc_unchanged"]["rate"] == 20.0  # 2 findings in 0.1 KLOC
    assert m["precision"]["rate"] == round(1 / (1 + 1 + 2), 6)
    low, high = m["detection"]["ci95"]
    assert 0.0 <= low <= m["detection"]["rate"] <= high <= 1.0


def test_bootstrap_resamples_whole_repositories_and_is_deterministic():
    frame, _ = frame_and_findings()
    again, _ = frame_and_findings()
    assert np.array_equal(frame.weights, again.weights)
    assert (frame.weights.sum(axis=1) == frame.groups).all()  # every resample draws as many repos as exist


def test_python_subset_leaves_out_javascript_pairs():
    frame, findings = frame_and_findings()
    ev = evaluate_tool(frame, "t", findings)
    assert metrics_for(frame, ev, ("python",))["pairs"] == 3


def test_overlap_counts():
    frame, findings = frame_and_findings()
    a = evaluate_tool(frame, "a", findings)
    b = evaluate_tool(frame, "b", {("b", "p4"): [("x", 20, 20, ("cmdi",))]})
    o = overlap(frame, {"a": a, "b": b}, "a", "b", ("python", "javascript"))
    assert (o["both"], o["only_a"], o["only_b"], o["neither"]) == (0, 1, 1, 1)
    assert o["union_detection"]["k"] == 2


def test_unmapped_findings_are_not_alerts_but_count_as_findings():
    frame, findings = frame_and_findings()
    findings[("u", "u1")] = [("py.assert", 1, 1, ()), ("py.hash", 2, 2, ("hash",))]
    ev = evaluate_tool(frame, "t", findings)
    m = metrics_for(frame, ev, ("python",))
    assert m["false_alarms_per_kloc_unchanged"]["rate"] == 10.0  # one alert in 0.1 KLOC
    assert ev.unmapped_rules["python"] == {"py.assert": 1}
    assert m["all_findings_per_kloc_after_and_unchanged"]["k"] == 3  # the after-file finding and both unchanged ones


def test_fix_weighted_detection_counts_each_commit_once():
    pairs = [
        pair("big1", "o/a", ["cmdi"], CODE, FIXED, commit="big"),
        pair("big2", "o/a", ["cmdi"], CODE, FIXED, commit="big"),
        pair("big3", "o/a", ["cmdi"], CODE, FIXED, commit="big"),
        pair("one", "o/b", ["cmdi"], CODE, FIXED, commit="small"),
    ]
    frame = Frame(pairs, [], reps=20, seed=1)
    found = {("b", "one"): [("py.os.system", 20, 20, ("cmdi",))]}
    m = metrics_for(frame, evaluate_tool(frame, "t", found), ("python",))
    assert m["detection"]["rate"] == 0.25  # one of four files
    assert m["detection_fix_weighted"]["rate"] == 0.5  # one of two fixes
