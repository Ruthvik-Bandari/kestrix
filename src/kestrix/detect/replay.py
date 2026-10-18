# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Replay a rule through the engine and score matches against labels (FR05, section 10)."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.errors import Reason, Rejected
from .engine import Elasticsearch
from .fixtures import Dataset
from .mapping import FieldMapping, to_lucene
from .rule import Rule


@dataclass(frozen=True)
class ReplayResult:
    rule_sha256: str
    mapping_sha256: str
    dataset_sha256: str
    query: str | None
    matched_ids: frozenset[str]
    tp: int
    fp: int
    fn: int
    tn: int
    unknown_matched: int
    scenarios_expected: frozenset[str]
    scenarios_detected: frozenset[str]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_sha256": self.rule_sha256,
            "mapping_sha256": self.mapping_sha256,
            "dataset_sha256": self.dataset_sha256,
            "query": self.query,
            "error": self.error,
            # An errored replay has no counts: reporting FN = every attack would read as "missed all".
            "counts": None
            if self.error
            else {
                "tp": self.tp,
                "fp": self.fp,
                "fn": self.fn,
                "tn": self.tn,
                "unknown_matched": self.unknown_matched,
            },
            "scenarios_expected": sorted(self.scenarios_expected),
            "scenarios_detected": sorted(self.scenarios_detected),
            "matched_event_ids": sorted(self.matched_ids),
        }


def score(
    rule: Rule,
    mapping: FieldMapping,
    dataset: Dataset,
    query: str | None,
    matched: frozenset[str],
    *,
    error: str | None = None,
) -> ReplayResult:
    malicious, benign, unknown = dataset.ids("malicious"), dataset.ids("benign"), dataset.ids("unknown")
    # A malicious event without a scenario_id is its own mandatory scenario, so it can never be dropped silently.
    attacks = [(e.scenario_id or f"event:{e.event_id}", e.event_id) for e in dataset.events if e.label == "malicious"]
    expected = frozenset(s for s, _ in attacks)
    detected = frozenset(s for s, eid in attacks if eid in matched)
    return ReplayResult(
        rule_sha256=rule.sha256,
        mapping_sha256=mapping.sha256,
        dataset_sha256=dataset.sha256,
        query=query,
        matched_ids=matched,
        tp=len(malicious & matched),
        fp=len(benign & matched),
        fn=len(malicious - matched),
        tn=len(benign - matched),
        unknown_matched=len(unknown & matched),
        scenarios_expected=expected,
        scenarios_detected=detected,
        error=error,
    )


class Replayer:
    """Holds one loaded index per dataset so candidates replay without re-indexing."""

    def __init__(self, engine: Elasticsearch, index: str, dataset: Dataset) -> None:
        self.engine, self.index, self.dataset = engine, index, dataset

    def run(self, rule: Rule, mapping: FieldMapping) -> ReplayResult:
        """Engine and conversion failures become an errored result, never zero matches."""
        query = None
        try:
            query = to_lucene(rule, mapping)
            matched = self.engine.search_ids(self.index, query).matched_ids
        except Rejected as exc:
            if exc.reason is Reason.ENGINE_UNAVAILABLE:
                raise
            return score(rule, mapping, self.dataset, query, frozenset(), error=f"{exc.reason}: {exc.detail}")
        return score(rule, mapping, self.dataset, query, matched)
