# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev metrics report and the one-time locked test evaluation. Aggregates only: no URLs, names, ids or groups."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kestrixmailbench.metrics import REPS, SEED, Frame
from kestrixvul.evaluate import LockedClaim, claim_locked, finish_claim

from .common import Layout, LinkFileBenchError, file_sha256, now, write_json
from .features import code_versions, feature_errors, read_features
from .leakage import leakage_report
from .metrics import file_report, link_report
from .realurls import realurl_report

BOOTSTRAP_UNIT = {
    "link": "registered domain (offline approximation)",
    "file": "Govdocs1 thread",
    "realurl": "sampled domain or platform host",
}
REPORT = "{kind}-dev-metrics.json"
LOCKED_REPORT = "{kind}-locked-{name}.json"


def system_report(kind: str, frame: Frame, reps: int, seed: int) -> dict[str, Any]:
    if kind == "realurl":
        return realurl_report(frame, reps, seed)
    if kind == "link":
        return {**link_report(frame, reps, seed), "leakage": leakage_report(frame, reps, seed)}
    return file_report(frame, reps, seed)


def _header(layout: Layout, kind: str, split: str, reps: int, seed: int) -> dict[str, Any]:
    manifest = layout.split_manifest
    return {
        "schema_version": 1,
        "kind": kind,
        "split": split,
        "generated_at": now(),
        "bootstrap": {"resamples": reps, "seed": seed, "unit": BOOTSTRAP_UNIT[kind]},
        "split_manifest_sha256": file_sha256(manifest) if manifest.is_file() else None,
        "code": sorted(v or "unrecorded" for v in code_versions(layout, split)),
    }


def dev_metrics(layout: Layout, kind: str, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """Metrics, error analysis and (links) leakage controls on dev; writes ``<kind>-dev-metrics.json``."""
    frame = Frame(read_features(layout, "dev"))
    body = {
        **_header(layout, kind, "dev", reps, seed),
        "items": len(frame),
        "feature_errors": feature_errors(layout),
        **system_report(kind, frame, reps, seed),
    }
    write_json(layout.reports / REPORT.format(kind=kind), body)
    return body


def _check_same_rules(layout: Layout, label: str) -> str:
    dev, test = code_versions(layout, "dev"), code_versions(layout, "test")
    if len(dev) != 1 or dev != test or None in dev:
        raise LinkFileBenchError(
            f"{label}: dev features come from code {sorted(map(str, dev))} and test features from "
            f"{sorted(map(str, test))}; run both with the same synced code (jobs record KESTRIX_GIT_SHA)"
        )
    (version,) = dev
    assert version is not None
    return version


def locked_test(
    layout: Layout,
    kind: str,
    name: str,
    reps: int = REPS,
    seed: int = SEED,
    *,
    baseline: Layout | None = None,
) -> Path:
    """Evaluate the final rules (and, when given, the baseline rules) on the locked test split, once.

    Everything that can fail is exercised on dev rows before the lock is claimed, so a typo cannot burn the one
    evaluation; after the claim the lock stays even if the run fails. The test features must come from the same
    code version as the dev features (and the baseline's from its own), recorded by the features jobs.
    """
    roots = {"final": layout, **({"baseline": baseline} if baseline else {})}
    versions = {label: _check_same_rules(lay, label) for label, lay in roots.items()}
    if baseline and baseline.split_manifest.read_bytes() != layout.split_manifest.read_bytes():
        # The round roots copy the split manifest, so the two must be byte-identical.
        raise LinkFileBenchError("the baseline and final roots have different split manifests")
    for lay in roots.values():
        for shard in range(lay.shards):
            if not lay.feature_file(shard, "test").is_file():
                raise LinkFileBenchError(f"{lay.feature_file(shard, 'test')} is missing; run the features job first")
    for lay in roots.values():
        dev_rows = read_features(lay, "dev")
        system_report(kind, Frame(dev_rows[:: max(1, len(dev_rows) // 3000)]), 2, seed)
    claim = claim_locked(
        layout.root,
        {
            "name": name,
            "kind": kind,
            "code": versions,
            "split_manifest_sha256": file_sha256(layout.split_manifest),
        },
    )
    systems = {
        label: system_report(kind, Frame(read_features(lay, "test", claim)), reps, seed) for label, lay in roots.items()
    }
    body = {
        **_header(layout, kind, "test", reps, seed),
        "name": name,
        "code_by_system": versions,
        "feature_errors": {label: feature_errors(lay) for label, lay in roots.items()},
        "systems": systems,
    }
    out = layout.reports / LOCKED_REPORT.format(kind=kind, name=name)
    write_json(out, body)
    finish_claim(claim, out)
    return out


__all__ = ["LockedClaim", "dev_metrics", "locked_test"]
