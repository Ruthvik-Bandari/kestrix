# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark evaluation of a repair system over the generated cases (plan section 13).

Each case runs through the system on the pinned engine. Results are scored against the case's
expected outcome:

- ``success``:
  - ``repaired`` cases count only when the repair passed independent validation, so
    provisional repairs are not successes, and a mapping case must be repaired by a mapping patch;
  - ``insufficient_evidence`` and ``unchanged`` cases count when that exact outcome is returned.
- ``wrong_change``: the system changed something it should not have. That is any ``repaired``
  outcome on a healthy or missing-telemetry case, or a repair with the wrong patch kind.
- ``abstained``: the system returned no repair. Abstentions and failures stay in the denominator.
- ``outcome_match`` (secondary): the expected outcome, counting provisional repairs, which were
  repaired but had no validation suite. A repair that matched more benign development events than
  the original does not count, because it weakened the rule. It is reported beside, never instead
  of, ``success``.

Confidence intervals are percentile bootstraps that resample roots, not cases, because the
variants of one root are correlated. The locked test split is evaluated only on request
(``locked=True``), after a system is chosen.

Results hold case ids, root ids, outcomes and counts, never event values.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.core.safe_load import load_yaml
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.workflow import Inputs
from kestrix.detect.workflow import run as b0_run

System = Callable[[Inputs, Elasticsearch], dict[str, Any]]


def _b0(cases_root: Path) -> System:
    return b0_run


def _b1(cases_root: Path) -> System:
    from .b1 import build_memory, generator

    propose = generator(build_memory(cases_root))  # train split only
    return lambda inputs, es: b0_run(inputs, es, generator=propose)


# Per-run counters a system may record (B2: model calls, valid and dropped proposals).
SYSTEM_STATS: dict[str, int] = {}


def _b2(cases_root: Path) -> System:
    import os

    from .b2 import generator
    from .hf import load

    snapshot = os.environ.get("KESTRIX_B2_SNAPSHOT")
    if not snapshot:
        raise ValueError("set KESTRIX_B2_SNAPSHOT to the local model snapshot (research/hpc/detect/fetch_model.sh)")
    propose = generator(load(Path(snapshot)), SYSTEM_STATS)
    return lambda inputs, es: b0_run(inputs, es, generator=propose)


def _m1(cases_root: Path) -> System:
    import os

    from .b2 import generator
    from .hf import load

    snapshot, adapter = os.environ.get("KESTRIX_B2_SNAPSHOT"), os.environ.get("KESTRIX_M1_ADAPTER")
    if not (snapshot and adapter):
        raise ValueError("set KESTRIX_B2_SNAPSHOT and KESTRIX_M1_ADAPTER (the trained LoRA adapter directory)")
    propose = generator(load(Path(snapshot), Path(adapter)), SYSTEM_STATS)
    return lambda inputs, es: b0_run(inputs, es, generator=propose)


# System factories: each builds its system from the case root (B1 reads its train-split memory).
SYSTEMS: dict[str, Callable[[Path], System]] = {"b0": _b0, "b1": _b1, "b2": _b2, "m1": _m1}
BOOTSTRAP_REPS = 2000
OPEN_SPLITS = ("train", "development")


def load_case(case_dir: Path) -> tuple[dict[str, Any], Inputs]:
    manifest = load_yaml((case_dir / "case.yml").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"{case_dir.name}: malformed case.yml")

    def text(name: str) -> str | None:
        path = case_dir / name
        return path.read_text(encoding="utf-8") if path.is_file() else None

    validation = case_dir / "validation.jsonl"
    return manifest, Inputs(
        rule_text=(case_dir / "rule.yml").read_text(encoding="utf-8"),
        mapping_text=(case_dir / "mapping.yml").read_text(encoding="utf-8"),
        dev_path=case_dir / "development.jsonl",
        validation_path=validation if validation.is_file() else None,
        healthy_rule_text=text("healthy_rule.yml"),
        healthy_mapping_text=text("healthy_mapping.yml"),
    )


def _adds_false_alarms(report: dict[str, Any]) -> bool:
    """True when the selected repair matched more benign development events than the healthy
    reference does (or than the original, when no healthy reference was replayed). A correct repair
    may match confounders the healthy rule also matches; only exceeding that is weakening."""
    healthy = ((report.get("healthy_reference") or {}).get("development") or {}).get("counts") or {}
    original = healthy or ((report.get("original") or {}).get("development") or {}).get("counts") or {}
    chosen = next(
        (c for c in report.get("candidates") or [] if c["candidate"]["proposal_id"] == report.get("selected")), None
    )
    counts = ((chosen or {}).get("development") or {}).get("counts") or {}
    return bool(original and counts) and counts.get("fp", 0) > original.get("fp", 0)


# Workflow exits that mean the engine, not the system, failed. They are errors, so an outage never
# silently lowers one system's numbers in a paired comparison.
_ENGINE_FAILURE_PREFIXES = (
    "original replay failed",
    "original validation replay failed",
    "healthy reference replay failed",
)


def _engine_failure(report: dict[str, Any] | None) -> str | None:
    if report is None:
        return None
    if report.get("outcome") == "engine_unavailable":
        return f"engine_unavailable: {report.get('reason')}"
    reason = str(report.get("reason") or "")
    return reason[:200] if reason.startswith(_ENGINE_FAILURE_PREFIXES) else None


def score(manifest: dict[str, Any], report: dict[str, Any] | None, error: str | None = None) -> dict[str, Any]:
    error = error or _engine_failure(report)
    if error is not None:
        report = None
    expected = manifest["expected"]
    outcome = report["outcome"] if report else "error"
    provisional = bool(report and report.get("provisional"))
    patch_kind = (report or {}).get("artifact", {}).get("kind") if outcome == "repaired" else None
    adds_false_alarms = outcome == "repaired" and report is not None and _adds_false_alarms(report)
    want = expected["outcome"]
    if want == "repaired":
        right_kind = "patch_kind" not in expected or patch_kind == expected["patch_kind"]
        success = outcome == "repaired" and not provisional and right_kind
        wrong = outcome == "repaired" and not right_kind
    else:
        success = outcome == want
        wrong = outcome == "repaired"
    return {
        "case_id": manifest["case_id"],
        "root_id": manifest["root_id"],
        "split": manifest["split"],
        "kind": manifest["fault"]["kind"],
        "expected": want,
        "outcome": outcome,
        "provisional": provisional,
        "patch_kind": patch_kind,
        "has_validation": bool(manifest.get("validation")),
        "success": success,
        # Secondary: the expected outcome, counting provisional repairs (no validation suite), unless the
        # repair bought its coverage with new false alarms on the development events (a weakened rule).
        "outcome_match": outcome == want
        and (want != "repaired" or "patch_kind" not in expected or patch_kind == expected["patch_kind"])
        and not adds_false_alarms,
        "adds_false_alarms": adds_false_alarms,
        "wrong_change": wrong,
        "abstained": outcome == "abstained",
        "error": error,
    }


def run_cases(cases_root: Path, system: System, es: Elasticsearch, *, locked: bool = False) -> list[dict[str, Any]]:
    splits = (*OPEN_SPLITS, "test") if locked else OPEN_SPLITS
    rows = []
    for split in splits:
        for case_dir in sorted(p for p in (cases_root / split).glob("*") if (p / "case.yml").is_file()):
            manifest, inputs = load_case(case_dir)
            if manifest.get("split") != split:
                raise ValueError(
                    f"{case_dir.name}: case.yml says split {manifest.get('split')!r}, folder says {split!r}"
                )
            try:
                rows.append(score(manifest, system(inputs, es)))
            except Rejected as exc:  # an invalid case or engine failure is an error, never a pass
                rows.append(score(manifest, None, f"{exc.reason}: {exc.detail}"[:200]))
    return rows


def _rate(rows: list[dict[str, Any]], key: str) -> float | None:
    return sum(bool(r[key]) for r in rows) / len(rows) if rows else None


def bootstrap(rows: list[dict[str, Any]], key: str, seed: int = 0, reps: int = BOOTSTRAP_REPS) -> list[float] | None:
    """95% percentile interval of ``key``'s rate, resampling roots with replacement."""
    by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_root[r["root_id"]].append(r)
    roots = sorted(by_root)
    if len(roots) < 2:
        return None
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    stats = []
    for _ in range(reps):
        sample = [r for root in rng.choices(roots, k=len(roots)) for r in by_root[root]]
        stats.append(sum(bool(r[key]) for r in sample) / len(sample))
    stats.sort()
    return [round(stats[int(0.025 * reps)], 4), round(stats[int(0.975 * reps) - 1], 4)]


def summarize(rows: Iterable[dict[str, Any]], seed: int = 0) -> dict[str, Any]:
    rows = list(rows)

    def block(subset: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "cases": len(subset),
            "roots": len({r["root_id"] for r in subset}),
            "success_rate": _rate(subset, "success"),
            "success_ci95": bootstrap(subset, "success", seed),
            "outcome_match_rate": _rate(subset, "outcome_match"),
            "wrong_change_rate": _rate(subset, "wrong_change"),
            "abstention_rate": _rate(subset, "abstained"),
            "provisional_repairs": sum(r["provisional"] for r in subset),
            "errors": sum(r["error"] is not None for r in subset),
            "outcomes": dict(sorted(_count(r["outcome"] for r in subset).items())),
        }

    return {
        "overall": block(rows),
        "by_split": {s: block([r for r in rows if r["split"] == s]) for s in sorted({r["split"] for r in rows})},
        "by_kind": {k: block([r for r in rows if r["kind"] == k]) for k in sorted({r["kind"] for r in rows})},
        "with_validation_suite": block([r for r in rows if r["has_validation"]]),
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for v in values:
        out[v] += 1
    return dict(out)
