# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Paired comparison of repair systems on identical cases (plan section 13, "Comparison design").

Every system must have been evaluated on exactly the same case ids; anything else is refused. For
each system against the baseline, the per-case success difference is averaged. Its 95% interval
comes from a bootstrap that resamples roots, because a root's variants are correlated. The
results are an exploratory estimate on a small benchmark, and the output says so.
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any

from .evaluate import BOOTSTRAP_REPS


class CompareError(ValueError):
    pass


def _paired(base: dict[str, dict[str, Any]], other: dict[str, dict[str, Any]]) -> dict[str, list[int]]:
    """root -> per-case success differences (other - base)."""
    diffs: dict[str, list[int]] = defaultdict(list)
    for case_id, row in base.items():
        diffs[row["root_id"]].append(int(other[case_id]["success"]) - int(row["success"]))
    return diffs


def _bootstrap_mean(by_root: dict[str, list[int]], seed: int, reps: int) -> list[float] | None:
    roots = sorted(by_root)
    if len(roots) < 2:
        return None
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    stats = []
    for _ in range(reps):
        sample = [d for r in rng.choices(roots, k=len(roots)) for d in by_root[r]]
        stats.append(sum(sample) / len(sample))
    stats.sort()
    return [round(stats[int(0.025 * reps)], 4), round(stats[int(0.975 * reps) - 1], 4)]


def compare(
    reports: dict[str, dict[str, Any]],
    baseline: str,
    seed: int = 0,
    reps: int = BOOTSTRAP_REPS,
    splits: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Compare on held-out cases only. B1's memory and M1's training data are the train split, so
    train cases would score those systems on their own data. The default is ``development``, or
    ``test`` for a locked evaluation."""
    if baseline not in reports:
        raise CompareError(f"baseline {baseline!r} has no report")
    locked_flags = {rep.get("locked_test_included", False) for rep in reports.values()}
    if len(locked_flags) != 1:
        raise CompareError("mixing locked and open evaluations")
    scope = splits or (("test",) if True in locked_flags else ("development",))
    rows = {name: {r["case_id"]: r for r in rep["cases"] if r["split"] in scope} for name, rep in reports.items()}
    if not rows[baseline]:
        raise CompareError(f"no {'/'.join(scope)} cases in the baseline report")
    ids = set(rows[baseline])
    for name, by_case in rows.items():
        if set(by_case) != ids:
            raise CompareError(f"{name} was evaluated on different cases than {baseline}; comparisons must be paired")
    out: dict[str, Any] = {
        "schema_version": 1,
        "baseline": baseline,
        "cases": len(ids),
        "roots": len({r["root_id"] for r in rows[baseline].values()}),
        "locked_test_included": locked_flags.pop(),
        "splits": list(scope),
        "note": "Exploratory: a small benchmark of synthetic faults on public telemetry; intervals resample roots.",
        "systems": {},
    }
    kinds = sorted({r["kind"] for r in rows[baseline].values()})
    for name, by_case in sorted(rows.items()):
        entry: dict[str, Any] = {
            "success_rate": round(sum(r["success"] for r in by_case.values()) / len(by_case), 4),
            "outcome_match_rate": round(sum(r.get("outcome_match", False) for r in by_case.values()) / len(by_case), 4),
            "wrong_change_rate": round(sum(r["wrong_change"] for r in by_case.values()) / len(by_case), 4),
            "abstention_rate": round(sum(r["abstained"] for r in by_case.values()) / len(by_case), 4),
            "by_kind": {
                k: round(
                    sum(r["success"] for r in by_case.values() if r["kind"] == k)
                    / sum(1 for r in by_case.values() if r["kind"] == k),
                    4,
                )
                for k in kinds
            },
        }
        if name != baseline:
            diffs = _paired(rows[baseline], by_case)
            flat = [d for ds in diffs.values() for d in ds]
            entry["vs_baseline"] = {
                "mean_success_difference": round(sum(flat) / len(flat), 4),
                "ci95": _bootstrap_mean(diffs, seed, reps),
                "cases_won": sum(d > 0 for d in flat),
                "cases_lost": sum(d < 0 for d in flat),
            }
        out["systems"][name] = entry
    return out


def markdown(result: dict[str, Any]) -> str:
    lines = [
        f"Paired on {result['cases']} cases from {result['roots']} roots"
        + f" ({' + '.join(result['splits'])} split)"
        + f"; baseline {result['baseline']}. {result['note']}",
        "",
        "| System | Validated success | Outcome match (incl. provisional) | Wrong change | Abstained | Δ success vs baseline (95% CI) | Won / lost |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, s in result["systems"].items():
        vs = s.get("vs_baseline")
        delta = (
            f"{vs['mean_success_difference']:+.3f} ({vs['ci95'][0]:+.3f} to {vs['ci95'][1]:+.3f})"
            if vs and vs["ci95"]
            else "—"
        )
        won = f"{vs['cases_won']} / {vs['cases_lost']}" if vs else "—"
        lines.append(
            f"| {name} | {s['success_rate']:.3f} | {s['outcome_match_rate']:.3f} | {s['wrong_change_rate']:.3f} | {s['abstention_rate']:.3f} | {delta} | {won} |"
        )
    return "\n".join(lines) + "\n"
