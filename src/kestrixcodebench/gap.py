# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Where Bandit detects a pair and kestrix does not: counts by Bandit test id and family, aggregates only.

For the in-scope pairs of one language subset, a pair is a *gap* pair when Bandit has a finding of one of the pair's
families near a changed line and kestrix has none. The report counts gap pairs per Bandit test id and per family, and
gives each test id's noise (alerts on after-files and unchanged files per KLOC) next to its true hits, so a rule worth
writing is one with many gap pairs and few alerts per hit. No code, paths or repository names.

Both tools must have been scanned on the same split: ``--tool-run kestrix=RUN --tool-run bandit=RUN``.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .common import SHARDS, Layout, write_json
from .metrics import SUBSETS, evaluate_tool, read_findings
from .report import load_frame


def bandit_gap(layout: Layout, runs: dict[str, str], split: str, label: str, subset: str = "python") -> Any:
    """Write ``reports/codebench-gap-LABEL.json``."""
    frame = load_frame(layout, split, reps=2)
    evals = {
        tool: evaluate_tool(frame, tool, read_findings(layout, runs[tool], tool, SHARDS))
        for tool in ("kestrix", "bandit")
    }
    languages = SUBSETS[subset]
    in_subset = frame.mask(languages)
    by_rule: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    by_rule_family: Counter[str] = Counter()
    detected: Counter[str] = Counter()
    scope = both = only_bandit = only_kestrix = 0
    for i, row in enumerate(frame.pairs):
        if not in_subset[i] or not row["families"]:
            continue
        scope += 1
        theirs, ours = evals["bandit"].pair_evals[i], evals["kestrix"].pair_evals[i]
        if theirs.matched:
            detected.update(theirs.rule_tp.keys())
        if theirs.matched and ours.matched:
            both += 1
        elif ours.matched:
            only_kestrix += 1
        elif theirs.matched:
            only_bandit += 1
            by_rule.update(theirs.rule_tp.keys())
            by_family.update(theirs.matched)
            for rule in theirs.rule_tp:
                by_rule_family[f"{rule} {'+'.join(sorted(theirs.matched))}"] += 1
    kloc = float(
        (frame.after_kloc * (in_subset & frame.is_pair)).sum() + (frame.unch_kloc * (in_subset & ~frame.is_pair)).sum()
    )
    noise = evals["bandit"].alert_rules.get("python", Counter())
    rules = [
        {
            "rule": rule,
            "gap_pairs": n,
            "detected_pairs": detected[rule],
            "alerts_on_fixed_and_unchanged": noise[rule],
            "alerts_per_kloc": round(noise[rule] / kloc, 4) if kloc else None,
        }
        for rule, n in by_rule.most_common()
    ]
    out = {
        "schema_version": 1,
        "split": split,
        "subset": subset,
        "runs": runs,
        "pairs_in_scope": scope,
        "both": both,
        "only_bandit": only_bandit,
        "only_kestrix": only_kestrix,
        "by_bandit_test": rules,
        "by_family": dict(by_family.most_common()),
        "by_bandit_test_and_family": dict(by_rule_family.most_common()),
    }
    path = layout.reports / f"codebench-gap-{label}.json"
    write_json(path, out)
    return path


__all__ = ["bandit_gap"]
