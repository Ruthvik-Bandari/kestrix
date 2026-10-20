# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Deterministic diagnosis: field coverage and failure-family hypotheses (FR02, FR03).

Hypotheses come from schema evidence and labeled replay differences. Several may hold
at once; ambiguous evidence returns every plausible family instead of guessing one.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

from ..core.enums import TextEnum
from .fixtures import Dataset, SchemaProfile, lookup, profile
from .mapping import FieldMapping
from .replay import ReplayResult
from .rule import Predicate, Rule


class Family(TextEnum):
    MAPPING = "mapping"
    MISSING_TELEMETRY = "missing_telemetry"
    NOISE = "noise"
    LOGIC = "logic"


@dataclass(frozen=True)
class FieldCoverage:
    sigma_field: str
    index_field: str
    mapped: bool
    present: int
    total: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Hypothesis:
    family: Family
    reason_codes: tuple[str, ...]
    fields: tuple[str, ...] = ()
    evidence_event_ids: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family.value,
            "reason_codes": list(self.reason_codes),
            "fields": list(self.fields),
            "evidence_event_ids": list(self.evidence_event_ids),
            "alternative_index_fields": list(self.alternatives),
        }


# Collection guidance for missing telemetry. A recommendation, never an automatic repair.
_GUIDANCE = {
    "CommandLine": (
        "Collect process command lines. Sysmon Event ID 1 records CommandLine by default; for Security event "
        "4688 enable 'Include command line in process creation events' (Administrative Templates > System > "
        "Audit Process Creation)."
    ),
    "ParentImage": (
        "Collect parent process paths. Sysmon Event ID 1 records ParentImage; Security event 4688 includes "
        "'Creator Process Name' on Windows 10 / Server 2016 and later."
    ),
}
_DEFAULT_GUIDANCE = "Collect the '{field}' field (Sysmon Event ID 1, process creation) and re-ingest the telemetry."

_MAX_ALTERNATIVES = 4
_MAX_EVIDENCE = 64
_NON_ALNUM = re.compile(r"[^a-z0-9]")


def guidance(sigma_field: str) -> str:
    return _GUIDANCE.get(sigma_field, _DEFAULT_GUIDANCE.format(field=sigma_field))


def coverage(rule: Rule, mapping: FieldMapping, schema: SchemaProfile) -> list[FieldCoverage]:
    return [
        FieldCoverage(
            f, mapping.target(f), f in mapping.fields, schema.presence(mapping.target(f)), schema.total_events
        )
        for f in sorted(rule.fields)
    ]


def _norm(name: str) -> str:
    return _NON_ALNUM.sub("", name.lower())


def _hits(predicates: list[Predicate], value: object) -> bool:
    """Heuristic value check used only to *propose* alternative fields. It is not a
    matcher: every proposal is still replayed on the pinned engine before acceptance."""
    if not isinstance(value, str):
        return False
    text = value.lower()
    tests: dict[str, Callable[[str], bool]] = {
        "equals": text.__eq__,
        "contains": text.__contains__,
        "startswith": text.startswith,
        "endswith": text.endswith,
    }
    return any((all if p.match_all else any)(tests[p.modifier](v.lower()) for v in p.values) for p in predicates)


def alternative_fields(
    rule: Rule, sigma_field: str, mapping: FieldMapping, schema: SchemaProfile, dataset: Dataset
) -> tuple[str, ...]:
    """Observed, unmapped string fields whose values fit the rule's predicates for ``sigma_field``
    on at least one labeled event (filters match benign events, so all labels count). Ranked by
    value hits, then name similarity."""
    taken = set(mapping.fields.values())
    target = _norm(sigma_field)
    predicates = [p for sel in rule.selections.values() for p in sel.predicates if p.field == sigma_field]
    scored = []
    for name, stats in schema.fields.items():
        # Parent and child process fields describe different processes and are never interchangeable.
        if name in taken or "str" not in stats.types or sigma_field.startswith("Parent") != ("parent" in name.lower()):
            continue
        ratio = max(
            difflib.SequenceMatcher(None, target, _norm(name.rsplit(".", 1)[-1])).ratio(),
            difflib.SequenceMatcher(None, target, _norm(name)).ratio(),
        )
        hits = sum(_hits(predicates, lookup(e.data, name)) for e in dataset.events)
        # A similar name alone is not evidence; the field must carry values the rule is looking for.
        if hits:
            scored.append((-hits, -ratio, name))
    return tuple(name for *_, name in sorted(scored)[:_MAX_ALTERNATIVES])


def hypotheses(
    rule: Rule, mapping: FieldMapping, schema: SchemaProfile, dataset: Dataset, original: ReplayResult
) -> list[Hypothesis]:
    found: list[Hypothesis] = []
    attack_schema = profile(e for e in dataset.events if e.label == "malicious")
    for cov in coverage(rule, mapping, schema):
        if cov.present and (attack_schema.total_events == 0 or attack_schema.presence(cov.index_field)):
            continue
        if cov.present:  # collected on benign hosts only: the attacks themselves carry no evidence
            found.append(
                Hypothesis(Family.MISSING_TELEMETRY, ("field_absent_on_malicious_events",), (cov.sigma_field,))
            )
            continue
        alts = alternative_fields(rule, cov.sigma_field, mapping, schema, dataset)
        if alts:
            found.append(
                Hypothesis(
                    Family.MAPPING,
                    ("mapped_field_absent", "similar_field_observed"),
                    (cov.sigma_field,),
                    alternatives=alts,
                )
            )
        else:
            found.append(Hypothesis(Family.MISSING_TELEMETRY, ("field_not_collected",), (cov.sigma_field,)))
    if original.error is not None:
        return found
    fp_ids = sorted(original.matched_ids & dataset.ids("benign"))
    fn_ids = sorted(dataset.ids("malicious") - original.matched_ids)
    if fp_ids:
        found.append(
            Hypothesis(Family.NOISE, ("benign_events_matched",), evidence_event_ids=tuple(fp_ids[:_MAX_EVIDENCE]))
        )
    fields_present = not any(h.family in (Family.MAPPING, Family.MISSING_TELEMETRY) for h in found)
    if fn_ids and fields_present:
        found.append(
            Hypothesis(
                Family.LOGIC, ("malicious_missed_fields_present",), evidence_event_ids=tuple(fn_ids[:_MAX_EVIDENCE])
            )
        )
    return found
