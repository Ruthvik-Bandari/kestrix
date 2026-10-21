# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev metrics report and the one-time locked test evaluation. Aggregates only: no ids, groups or text."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kestrixvul.evaluate import LockedClaim, claim_locked, finish_claim

from .common import Layout, MailBenchError, file_sha256, now, write_json
from .features import feature_errors, read_features
from .leakage import era_table, probe_separability
from .learn import model_scoring
from .metrics import (
    FEATURE_SETS,
    REPS,
    SEED,
    FeatureSet,
    Frame,
    Scoring,
    Stratum,
    baseline_scoring,
    causes,
    default_strata,
    strata_table,
    synthetic_table,
    table,
)

LOCKED_REPORT = "mail-locked-{name}.json"


def system_report(
    frame: Frame, scoring: Scoring, fset: FeatureSet, strata: list[Stratum], reps: int, seed: int
) -> dict[str, Any]:
    return {
        "feature_set": fset.to_json(),
        "metrics": table(frame, scoring, reps, seed),
        "same_era": strata_table(frame, scoring, strata, reps, seed),
        "causes": causes(frame, fset, scoring),
        "synthetic": synthetic_table(frame, scoring),
    }


def dev_metrics(
    layout: Layout, strata: list[Stratum] | None = None, reps: int = REPS, seed: int = SEED
) -> dict[str, Any]:
    """Baseline metrics on dev for every feature set, plus the leakage controls; writes the report."""
    strata = strata or default_strata()
    frame = Frame(read_features(layout, "dev"))
    manifest = layout.split_manifest
    body: dict[str, Any] = {
        "schema_version": 1,
        "split": "dev",
        "generated_at": now(),
        "bootstrap": {"resamples": reps, "seed": seed, "unit": "split group (source file or mailbox plus year)"},
        "split_manifest_sha256": file_sha256(manifest) if manifest.is_file() else None,
        "messages": len(frame),
        "feature_errors": feature_errors(layout),
        "baseline": {
            name: system_report(frame, baseline_scoring(frame, fset), fset, strata, reps, seed)
            for name, fset in FEATURE_SETS.items()
        },
        "leakage": {"era": era_table(frame), "probes_auc": probe_separability(frame, strata)},
    }
    write_json(layout.reports / "mail-dev-metrics.json", body)
    return body


def era_sensitive_ids(layout: Layout) -> tuple[str, ...]:
    path = layout.reports / "mail-dev-metrics.json"
    if not path.is_file():
        raise MailBenchError(f"{path} is missing; run dev-metrics first")
    return tuple(json.loads(path.read_text())["leakage"]["era"]["era_sensitive_ids"])


def load_model(path: Path) -> dict[str, Any]:
    try:
        model: dict[str, Any] = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise MailBenchError(f"cannot read weights file {path.name}: {exc}") from exc
    if model.get("kind") != "kestrix-mail-weights-candidate" or model.get("schema_version") != 1:
        raise MailBenchError(f"{path} is not a mail weights file")
    return model


def evaluate_systems(
    frame: Frame, models: dict[str, dict[str, Any]], strata: list[Stratum], reps: int, seed: int
) -> dict[str, Any]:
    systems: dict[str, Any] = {}
    for name, fset in FEATURE_SETS.items():
        systems[f"baseline:{name}"] = system_report(frame, baseline_scoring(frame, fset), fset, strata, reps, seed)
    for name, model in models.items():
        fset = FeatureSet.from_json(model["feature_set"])
        base = baseline_scoring(frame, fset)
        systems[f"baseline:{fset.name}"] = systems.get(f"baseline:{fset.name}") or system_report(
            frame, base, fset, strata, reps, seed
        )
        systems[f"learned:{name}"] = system_report(frame, model_scoring(frame, model), fset, strata, reps, seed)
    return systems


def locked_test(
    layout: Layout,
    weights: list[Path],
    name: str,
    strata: list[Stratum] | None = None,
    reps: int = REPS,
    seed: int = SEED,
) -> Path:
    """Evaluate baselines and the learned weights on the locked test split, once.

    Everything that can fail is exercised on dev rows before the lock is claimed, so a typo cannot
    burn the one evaluation; after the claim, the lock stays even if the run fails.
    """
    strata = strata or default_strata()
    models = {p.stem.removeprefix("mail-weights-"): load_model(p) for p in weights}
    if not models:
        raise MailBenchError("give at least one weights file")
    for shard in range(layout.shards):
        if not layout.feature_file(shard, "test").is_file():
            raise MailBenchError(f"{layout.feature_file(shard, 'test')} is missing; run the features job first")
    dev_rows = read_features(layout, "dev")
    evaluate_systems(Frame(dev_rows[:: max(1, len(dev_rows) // 1500)]), models, strata, 2, seed)
    claim = claim_locked(
        layout.root,
        {
            "name": name,
            "weights": {p.name: file_sha256(p) for p in weights},
            "split_manifest_sha256": file_sha256(layout.split_manifest),
        },
    )
    frame = Frame(read_features(layout, "test", claim))
    body = {
        "schema_version": 1,
        "split": "test",
        "name": name,
        "generated_at": now(),
        "bootstrap": {"resamples": reps, "seed": seed, "unit": "split group (source file or mailbox plus year)"},
        "split_manifest_sha256": file_sha256(layout.split_manifest),
        "weights_sha256": {p.name: file_sha256(p) for p in weights},
        "messages": len(frame),
        "feature_errors": feature_errors(layout),
        "systems": evaluate_systems(frame, models, strata, reps, seed),
    }
    out = layout.reports / LOCKED_REPORT.format(name=name)
    write_json(out, body)
    finish_claim(claim, out)
    return out


__all__ = ["LockedClaim", "dev_metrics", "locked_test"]
