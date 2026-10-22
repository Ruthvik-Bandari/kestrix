# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run ``kestrix.mail.analyze`` over one shard and store per-message features (never any message text).

A row holds the label, source, subset, year, group, split, the analyzer's verdict and heuristic score,
the findings as ``[id, severity, analyzer]``, the analyzer's counts and two header-era probes
(``received`` count and ``auth`` header count, used only by the leakage report). Features of the
locked test split go to their own files, which ``read_features`` opens only under a claimed lock.
"""

from __future__ import annotations

import base64
from collections import Counter
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.mail import analyze
from kestrix.mail.parse import parse_message

from .common import SPLITS, Layout, MailBenchError, read_jsonl, write_json, write_jsonl


def feature_row(data: bytes) -> dict[str, Any]:
    """Analyze one message offline and return the stored fields (no text, address or subject)."""
    report = analyze(data)
    parsed = parse_message(data)
    return {
        "verdict": report.verdict,
        "score": report.heuristic_score,
        "findings": [[f.id, f.severity, f.analyzer] for f in report.findings],
        "counts": report.counts.model_dump(),
        "received": parsed.received_count,
        "auth": len(parsed.authentication_results),
    }


def run_shard(
    layout: Layout,
    shard: int,
    meta: dict[str, dict[str, Any]],
    split_of: dict[str, str],
    splits: tuple[str, ...] = SPLITS,
) -> dict[str, Any]:
    """Analyze every message of ``shard`` in ``splits``; write one feature file per split and a count report.

    A split left out of ``splits`` is neither analyzed nor written: rule rounds pass ``("dev",)`` so the
    locked test messages are never even run through a changed analyzer.
    """
    rows: dict[str, list[dict[str, Any]]] = {side: [] for side in splits}
    errors: Counter[str] = Counter()
    path = layout.raw_shard(shard)
    if not path.is_file():
        raise MailBenchError(f"{path} is missing; run build first")
    for item in read_jsonl(path):
        info = meta[item["id"]]
        if split_of[item["id"]] not in splits:
            continue
        try:
            fields = feature_row(base64.b64decode(item["b64"]))
        except Rejected as exc:
            errors[exc.reason.value] += 1
            continue
        except Exception:
            errors["analyzer_error"] += 1
            continue
        row = {k: info[k] for k in ("id", "source", "subset", "label", "year", "group")}
        side = split_of[item["id"]]
        rows[side].append({**row, "split": side, **fields})
    for side in splits:
        write_jsonl(layout.feature_file(shard, side), rows[side])
    report = {
        "schema_version": 1,
        "shard": shard,
        "analyzed": {side: len(rows[side]) for side in splits},
        "errors": dict(sorted(errors.items())),
    }
    write_json(layout.feature_report(shard), report)
    return report


def read_features(layout: Layout, split: str, claim: object | None = None) -> list[dict[str, Any]]:
    """All feature rows of ``split``. The locked test needs ``claim`` (a ``LockedClaim``) and is refused without it."""
    if split not in SPLITS:
        raise MailBenchError(f"unknown split {split!r}")
    if split == "test":
        from kestrixvul.evaluate import LockedClaim

        if not isinstance(claim, LockedClaim) or not claim.path.is_file():
            raise MailBenchError("the locked test split is read only under a claimed LOCKED_EVAL.json")
    rows: list[dict[str, Any]] = []
    for shard in range(layout.shards):
        path: Path = layout.feature_file(shard, split)
        if not path.is_file():
            raise MailBenchError(f"{path} is missing; run the features job for every shard first")
        rows.extend(read_jsonl(path))
    rows.sort(key=lambda r: r["id"])
    return rows


def feature_errors(layout: Layout) -> dict[str, int]:
    """Analyzer errors summed over every shard report."""
    import json

    total: Counter[str] = Counter()
    for shard in range(layout.shards):
        path = layout.feature_report(shard)
        if path.is_file():
            total.update(json.loads(path.read_text())["errors"])
    return dict(sorted(total.items()))
