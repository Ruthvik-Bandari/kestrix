# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Find positive events for supported SigmaHQ rules by replay on the pinned Elasticsearch.

Every supported rule (one that parses and converts) is replayed against one disposable index
holding two event pools, both reduced to the v1 Sysmon EID 1 fields:

- ``sigma``: SigmaHQ regression events, each recorded as a true positive for a named rule;
- ``otrf``: OTRF recorded attack-simulation telemetry, unlabeled at event level.

Own-regression agreement measures replay fidelity: a rule should match the events SigmaHQ
recorded for it. OTRF matches are *candidate* positives that still need review before they are
labeled malicious. The report holds rule ids, dataset names and counts only, never field values.
Engine and conversion errors are reported as errors, never as "no match".
"""

from __future__ import annotations

import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kestrix.core.errors import Reason, Rejected
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Event
from kestrix.detect.mapping import to_lucene
from kestrix.detect.rule import PROCESS_CREATION_FIELDS, Rule, parse_rule

from .qc import (
    IDENTITY,
    MAX_EVENT_JSON_BYTES,
    MAX_METADATA_BYTES,
    MAX_SIGMA_BYTES,
    OTRF_WINDOWS,
    SIGMA_REGRESSION,
    SIGMA_RULES,
    _json_documents,
    _read_yaml,
    archive_key,
    is_sysmon_process_creation,
    iter_zip_records,
)


@dataclass(frozen=True)
class PoolEvent:
    event: Event
    pool: str  # "sigma" or "otrf"
    source: str  # rule id (sigma) or archive name (otrf)


def _v1_fields(fields: dict[str, Any]) -> dict[str, str]:
    """Keep only string values of the v1 process_creation fields; everything else is dropped."""
    return {k: v for k, v in fields.items() if k in PROCESS_CREATION_FIELDS and isinstance(v, str)}


def supported_rules(sigma_root: Path) -> tuple[dict[str, Rule], Counter[str]]:
    """Rules that parse and convert, keyed by rule id; rejections counted by reason."""
    rules: dict[str, Rule] = {}
    rejected: Counter[str] = Counter()
    for path in sorted((sigma_root / SIGMA_RULES).rglob("*.yml")):
        try:
            text = path.read_bytes()
            if len(text) > MAX_SIGMA_BYTES:
                rejected["input_too_large"] += 1
                continue
            rule = parse_rule(text.decode("utf-8"))
            to_lucene(rule, IDENTITY)
        except Rejected as exc:
            rejected[str(exc.reason)] += 1
            continue
        except UnicodeDecodeError:
            rejected["not_utf8"] += 1
            continue
        if rule.rule_id:
            rules[rule.rule_id] = rule
    return rules, rejected


def sigma_events(sigma_root: Path) -> Iterator[PoolEvent]:
    for info_path in sorted((sigma_root / SIGMA_REGRESSION).glob("*/info.yml")):
        try:
            info = _read_yaml(info_path, MAX_METADATA_BYTES)
        except Rejected:
            continue  # QC reports unreadable metadata
        if not isinstance(info, dict):
            continue
        for meta in info.get("rule_metadata") or []:
            if not (isinstance(meta, dict) and "id" in meta):
                continue
            rule_id = str(meta["id"])
            path = info_path.parent / f"{rule_id}.json"
            if not path.is_file() or path.stat().st_size > MAX_EVENT_JSON_BYTES:
                continue
            try:
                records = _json_documents(path.read_text(encoding="utf-8"))
            except (ValueError, Rejected):
                continue
            for n, record in enumerate(records):
                event = record.get("Event") if isinstance(record, dict) else None
                system = event.get("System") if isinstance(event, dict) else None
                data = event.get("EventData") if isinstance(event, dict) else None
                if isinstance(system, dict) and isinstance(data, dict) and is_sysmon_process_creation(system):
                    yield PoolEvent(
                        Event(f"sigma:{rule_id}:{n}", "malicious", rule_id, _v1_fields(data)), "sigma", rule_id
                    )


def otrf_events(otrf_root: Path) -> Iterator[PoolEvent]:
    windows = otrf_root / OTRF_WINDOWS
    for path in sorted(windows.rglob("*.zip")):
        key = archive_key(windows, path)
        try:
            for n, (_, rec) in enumerate(iter_zip_records(path)):
                if isinstance(rec, dict) and is_sysmon_process_creation(rec):
                    yield PoolEvent(Event(f"otrf:{key}:{n}", "unknown", None, _v1_fields(rec)), "otrf", key)
        except (ValueError, zipfile.BadZipFile, OSError):
            continue  # QC reports damaged archives


def expected_matches(sigma_root: Path) -> dict[str, int]:
    """SigmaHQ's declared ``match_count`` per rule, for regression folders that cover one rule.

    A regression file can hold context events that are not meant to match, so replay fidelity
    is measured against this declared count, not against the number of recorded events."""
    out: dict[str, int] = {}
    for info_path in sorted((sigma_root / SIGMA_REGRESSION).glob("*/info.yml")):
        try:
            info = _read_yaml(info_path, MAX_METADATA_BYTES)
        except Rejected:
            continue
        if not isinstance(info, dict):
            continue
        ids = [str(m["id"]) for m in info.get("rule_metadata") or [] if isinstance(m, dict) and "id" in m]
        counts = [t.get("match_count") for t in info.get("regression_tests_info") or [] if isinstance(t, dict)]
        if len(ids) == 1 and counts and all(isinstance(c, int) and not isinstance(c, bool) for c in counts):
            out[ids[0]] = sum(counts)  # type: ignore[arg-type]
    return out


def replay(
    rules: dict[str, Rule], pool: list[PoolEvent], es: Elasticsearch, expected: dict[str, int] | None = None
) -> dict[str, object]:
    """``expected`` holds SigmaHQ's declared match count per rule; fidelity is judged against it."""
    es.require_pinned()
    by_id = {p.event.event_id: p for p in pool}
    if len(by_id) != len(pool):
        raise Rejected(Reason.INVALID_FIXTURE, f"{len(pool) - len(by_id)} duplicate event ids in the replay pool")
    own_total = Counter(p.source for p in pool if p.pool == "sigma")
    per_rule: dict[str, dict[str, object]] = {}
    positives: dict[str, int] = {}  # own regression matches plus OTRF candidates
    disagree: list[str] = []
    errors: dict[str, str] = {}
    with es.replay_index([p.event for p in pool]) as index:
        for rule_id, rule in sorted(rules.items()):
            try:
                matched = es.search_ids(index, to_lucene(rule, IDENTITY)).matched_ids
            except Rejected as exc:
                errors[rule_id] = f"{exc.reason}: {exc.detail}"[:200]
                continue
            hits = [by_id[i] for i in matched]
            own = sum(h.pool == "sigma" and h.source == rule_id for h in hits)
            otrf = sorted({h.source for h in hits if h.pool == "otrf"})
            otrf_events = sum(h.pool == "otrf" for h in hits)
            positives[rule_id] = own + otrf_events
            if rule_id in (expected or {}) and own != (expected or {})[rule_id]:
                disagree.append(rule_id)
            per_rule[rule_id] = {
                "own_regression_events": own_total.get(rule_id, 0),
                "own_regression_matched": own,
                "own_regression_expected": (expected or {}).get(rule_id),
                "other_regression_matched": sum(h.pool == "sigma" and h.source != rule_id for h in hits),
                "otrf_candidate_events": otrf_events,
                "otrf_datasets": otrf,
                # Event ids only (pool:source:index), never values; the review sheet resolves them on the cluster.
                "matched_event_ids": sorted(matched),
            }
    checked = sum(1 for r in per_rule if r in (expected or {}))
    return {
        "schema_version": 1,
        "rules_replayed": len(per_rule),
        "engine_errors": errors,
        "pool": {
            "sigma_events": sum(p.pool == "sigma" for p in pool),
            "otrf_events": sum(p.pool == "otrf" for p in pool),
        },
        "fidelity": {
            "rules_with_declared_match_count": checked,
            "rules_matching_declared_count": checked - len(disagree),
            "rules_disagreeing": sorted(disagree),
        },
        "summary": {
            "rules_with_any_positive": sum(n > 0 for n in positives.values()),
            "rules_with_2plus_positive_events": sum(n >= 2 for n in positives.values()),
            "rules_with_otrf_candidates": sum(bool(v["otrf_datasets"]) for v in per_rule.values()),
        },
        "per_rule": per_rule,
    }


def run(root: Path, es: Elasticsearch) -> dict[str, object]:
    rules, rejected = supported_rules(root / "sigma")
    pool = [*sigma_events(root / "sigma"), *otrf_events(root / "otrf")]
    report = replay(rules, pool, es, expected_matches(root / "sigma"))
    report["rules_rejected"] = dict(sorted(rejected.items()))
    return report
