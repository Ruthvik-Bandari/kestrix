# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Impairment variants for each benchmark root (plan section 11, "Version one benchmark").

For every root rule in the split manifest, a healthy control (expected: unchanged) is written and
up to three faults are injected into the healthy reference, each with fault provenance ``synthetic``:

- ``mapping``: one field the rule uses is mapped to a stale index name (expected repair: mapping);
- ``missing_telemetry``: that field is removed from every event (expected: insufficient evidence);
- ``logic``: one condition edit (and/or swap, added or removed ``not``), or an ``endswith`` turned
  into an exact match.

Events are rewritten into an ECS layout, and the healthy mapping points every v1 field at its ECS
name. Every variant is verified on the pinned engine before it is kept: the healthy rule with the
healthy mapping must detect every positive, and the impaired case must miss at least one positive. Unlabeled
background events cannot count as false alarms, so a fault that only adds matches is not a fair
test. Variants that fail verification are discarded, with their reason counted.

Case folders contain raw event values. They are written privately on the cluster
(directory 0700, files 0600) and never committed. The aggregate report has counts only.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from kestrix.core.errors import Rejected
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Event
from kestrix.detect.mapping import FieldMapping, to_lucene
from kestrix.detect.repair import condition_mutations
from kestrix.detect.rule import Predicate, Rule, Selection, parse_rule

from .positives import PoolEvent, otrf_events, sigma_events

# Sysmon EID 1 field -> ECS-style index field (the healthy mapping).
ECS: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "CurrentDirectory": "process.working_directory",
    "OriginalFileName": "process.pe.original_file_name",
    "Company": "process.pe.company",
    "Product": "process.pe.product",
    "Description": "process.pe.description",
    "FileVersion": "process.pe.file_version",
    "Hashes": "process.hash.raw",
    "ProcessId": "process.pid",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "ParentProcessId": "process.parent.pid",
    "ParentUser": "process.parent.user.name",
    "User": "user.name",
    "LogonId": "winlog.logon.id",
    "IntegrityLevel": "winlog.event_data.IntegrityLevel",
}
HEALTHY = FieldMapping("bench-ecs", dict(ECS))
# Field preference for mapping / telemetry faults: the fields detections lean on most.
FAULT_FIELDS = ("CommandLine", "Image", "ParentImage", "OriginalFileName", "ParentCommandLine", "User")
NEGATIVES_PER_ROOT = 12
MAX_ATTEMPTS_PER_KIND = 64  # large expanded conditions can yield hundreds of one-edit mutations


@dataclass(frozen=True)
class Variant:
    kind: str
    rule: Rule
    mapping: FieldMapping
    events: tuple[Event, ...]
    detail: str
    expected: dict[str, str]


def to_ecs(flat: dict[str, str]) -> dict[str, Any]:
    nested: dict[str, Any] = {"event": {"code": "1"}}
    for field, value in flat.items():
        if field not in ECS:
            continue
        *parents, leaf = ECS[field].split(".")
        node = nested
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return nested


def _drop(data: dict[str, Any], dotted: str) -> dict[str, Any]:
    out = json.loads(json.dumps(data))
    *parents, leaf = dotted.split(".")
    node = out
    for part in parents:
        node = node.get(part, {})
    node.pop(leaf, None)
    return dict(out)


def _rank(seed: str, key: str) -> str:
    return hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()


def fixtures(root_id: str, positives: list[PoolEvent], negatives: list[PoolEvent]) -> list[Event]:
    """Positives get one scenario each. Negatives are labeled ``benign`` relative to this rule. They
    are either reviewed benign confounders, or background events the healthy reference does not
    match ("must not fire" for this rule, the healthy-reference oracle of plan section 10). A
    repair that weakens the rule until it matches them counts as a false alarm and fails
    validation; with ``unknown`` labels it would pass unnoticed."""
    events = [
        Event(f"{root_id}:p{i}", "malicious", f"S-{root_id}-{i}", to_ecs(p.event.data)) for i, p in enumerate(positives)
    ]
    events += [Event(f"{root_id}:n{i}", "benign", None, to_ecs(n.event.data)) for i, n in enumerate(negatives)]
    return events


def known_positives(manifest: dict[str, Any], malicious: set[str]) -> set[str]:
    """Every event that is a positive anywhere: any root's positives in any split, plus every event a
    reviewer labeled malicious. Such events are never used as another rule's benign background,
    or a test root's attack could appear as a negative in a train case."""
    out = set(malicious)
    for groups in manifest["splits"].values():
        for group in groups:
            for entry in group["rules"]:
                out.update(entry["positive_event_ids"])
    return out


def background_negatives(
    otrf_ids: list[str], matched: set[str], excluded: set[str], rule_id: str, seed: str
) -> list[str]:
    """A seeded sample of OTRF events the rule does not match and that are nobody's positive."""
    candidates = (e for e in otrf_ids if e not in matched and e not in excluded)
    return sorted(candidates, key=lambda e: _rank(seed, rule_id + e))[:NEGATIVES_PER_ROOT]


def _logic_rules(rule: Rule) -> Iterator[tuple[Rule, str]]:
    for cond in condition_mutations(rule.condition):
        yield replace(rule, condition=cond), "condition edited by one AST operation"
    for name, sel in rule.selections.items():
        for p in sel.predicates:
            if p.modifier == "endswith" and not p.match_all:
                exact = Predicate(p.field, "equals", p.values)
                branches = tuple(tuple(exact if q is p else q for q in b) for b in sel.branches)
                yield (
                    replace(rule, selections={**rule.selections, name: Selection(branches)}),
                    f"{name}.{p.field} endswith became an exact match",
                )


def candidates_for(rule: Rule, events: list[Event]) -> Iterator[Variant]:
    yield Variant("healthy", rule, HEALTHY, tuple(events), "no fault: healthy control", {"outcome": "unchanged"})
    used = [f for f in FAULT_FIELDS if f in rule.fields]
    for field in used[:1]:
        yield Variant(
            "mapping",
            rule,
            HEALTHY.with_field(field, f"winlog.event_data.{field}"),
            tuple(events),
            f"{field} mapped to winlog.event_data.{field}; data uses {ECS[field]}",
            {"outcome": "repaired", "family": "mapping", "patch_kind": "mapping"},
        )
        yield Variant(
            "missing_telemetry",
            rule,
            HEALTHY,
            tuple(replace(e, data=_drop(e.data, ECS[field])) for e in events),
            f"{field} ({ECS[field]}) is not collected",
            {"outcome": "insufficient_evidence", "family": "missing_telemetry"},
        )
    for impaired, detail in _logic_rules(rule):
        yield Variant("logic", impaired, HEALTHY, tuple(events), detail, {"outcome": "repaired", "family": "logic"})


def _matched(es: Elasticsearch, index: str, rule: Rule, mapping: FieldMapping) -> frozenset[str]:
    return es.search_ids(index, to_lucene(parse_rule(rule.to_yaml()), mapping)).matched_ids


def verify(
    es: Elasticsearch, rule: Rule, events: list[Event], variants: Iterable[Variant]
) -> tuple[list[Variant], Counter[str]]:
    """Keep at most one effective variant per kind; count why the others were discarded.

    Variants that keep the base events (mapping and logic faults) replay on one shared index; only
    variants that change the events (missing telemetry) need an index of their own."""
    discarded: Counter[str] = Counter()
    kept: dict[str, Variant] = {}
    malicious = {e.event_id for e in events if e.label == "malicious"}
    base = tuple(events)
    with es.replay_index(events) as base_index:
        healthy = _matched(es, base_index, rule, HEALTHY)
        if not malicious <= healthy:
            discarded["healthy_reference_misses_positive"] += 1
            return [], discarded
        attempts: Counter[str] = Counter()
        for variant in variants:
            if variant.kind in kept or attempts[variant.kind] >= MAX_ATTEMPTS_PER_KIND:
                continue
            attempts[variant.kind] += 1
            if variant.kind == "healthy":
                kept["healthy"] = variant  # the reference itself; verified above
                continue
            try:
                if variant.events == base:
                    got = _matched(es, base_index, variant.rule, variant.mapping)
                else:
                    with es.replay_index(list(variant.events)) as index:
                        got = _matched(es, index, variant.rule, variant.mapping)
            except Rejected as exc:
                discarded[f"engine:{exc.reason}"] += 1
                continue
            if got == healthy:
                discarded[f"{variant.kind}:no_behavior_change"] += 1
                continue
            # Every fault must cost a real detection, so the expected outcome (a repair that restores
            # coverage, or insufficient evidence) is the one the fault actually calls for.
            if malicious <= got:
                discarded[f"{variant.kind}:positives_still_detected"] += 1
                continue
            kept[variant.kind] = variant
    return list(kept.values()), discarded


def _private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _jsonl(events: Iterable[Event]) -> str:
    return "".join(
        json.dumps(
            {"event_id": e.event_id, "label": e.label, "scenario_id": e.scenario_id, "data": e.data}, sort_keys=True
        )
        + "\n"
        for e in events
    )


def _mapping_yaml(mapping: FieldMapping) -> str:
    return yaml.safe_dump(mapping.to_yaml_dict(), sort_keys=False)


def write_case(
    out: Path,
    root_id: str,
    split: str,
    variant: Variant,
    healthy: Rule,
    *,
    case_id: str | None = None,
    provenance: str = "synthetic",
) -> str:
    """One case folder in the format ``kestrix detect`` reads. Positives alternate between
    development and validation when there are two or more; otherwise there is no validation suite
    and any repair is reported as provisional."""
    case_id = case_id or f"{root_id}-{variant.kind}"
    d = out / split / case_id
    positives = [e for e in variant.events if e.label == "malicious"]
    negatives = [e for e in variant.events if e.label != "malicious"]
    dev = positives[::2] + negatives[::2]
    val = positives[1::2] + negatives[1::2] if len(positives) >= 2 else []
    _private(d / "rule.yml", variant.rule.to_yaml())
    _private(d / "healthy_rule.yml", healthy.to_yaml())
    _private(d / "mapping.yml", _mapping_yaml(variant.mapping))
    _private(d / "healthy_mapping.yml", _mapping_yaml(HEALTHY))
    _private(d / "development.jsonl", _jsonl(dev))
    if val:
        _private(d / "validation.jsonl", _jsonl(val))
    manifest = {
        "case_id": case_id,
        "root_id": root_id,
        "split": split,
        "provenance": provenance,
        "fault": {"kind": variant.kind, "detail": variant.detail},
        "expected": variant.expected,
        "validation": bool(val),
    }
    _private(d / "case.yml", yaml.safe_dump(manifest, sort_keys=False))
    return case_id


def build(
    root: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    *,
    benign: set[str],
    es: Elasticsearch,
    seed: str,
    malicious: set[str] | None = None,
) -> dict[str, object]:
    pool = {p.event.event_id: p for p in [*sigma_events(root / "sigma"), *otrf_events(root / "otrf")]}
    otrf_ids = sorted(k for k, p in pool.items() if p.pool == "otrf")
    excluded = known_positives(manifest, malicious or set())
    out = root / "benchmark" / "cases"
    kinds: Counter[str] = Counter()
    discarded: Counter[str] = Counter()
    per_split: Counter[str] = Counter()
    without_validation = 0
    roots_without_variants = 0
    for split, groups in manifest["splits"].items():
        if split == "reserve":
            continue
        for group in groups:
            for entry in group["rules"]:
                rule = parse_rule((root / "sigma" / entry["path"]).read_text(encoding="utf-8"))
                positives = [pool[e] for e in entry["positive_event_ids"]]
                matched = set(report["per_rule"].get(entry["id"], {}).get("matched_event_ids", []))
                confounders = [pool[e] for e in sorted(matched & benign)]
                background = background_negatives(otrf_ids, matched, excluded, entry["id"], seed)
                negatives = confounders + [pool[e] for e in background]
                events = fixtures(entry["id"], positives, negatives)
                kept, why = verify(es, rule, events, candidates_for(rule, events))
                discarded.update(why)
                roots_without_variants += not kept
                for variant in kept:
                    write_case(out, entry["id"], split, variant, rule)
                    kinds[variant.kind] += 1
                    per_split[split] += 1
                    without_validation += len(positives) < 2
    return {
        "schema_version": 1,
        "seed": seed,
        "cases": sum(kinds.values()),
        "cases_by_kind": dict(sorted(kinds.items())),
        "cases_by_split": dict(sorted(per_split.items())),
        "cases_without_validation_suite": without_validation,
        "roots_without_variants": roots_without_variants,
        "discarded": dict(sorted(discarded.items())),
    }
