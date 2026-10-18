"""Deterministic repair candidates (baseline B0, plan sections 9 and 12).

Generators propose small, bounded edits from schema and replay evidence. They make no
claim about behavior: every candidate is replayed on the engine and only kept when the
measured results improve without losing detected attack scenarios.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from .candidate import (
    MAX_CANDIDATES,
    AddExclusion,
    Candidate,
    MappingPatch,
    PredicateSpec,
    SetCondition,
    SetPredicate,
)
from .diagnose import Family, Hypothesis
from .fixtures import Dataset, lookup
from .mapping import FieldMapping
from .rule import MAX_VALUE_CHARS, And, Cond, Not, Or, Ref, Rule, render_condition, sigma_escape

# Context fields that may carry a narrow benign exclusion, most specific first.
# CommandLine is excluded on purpose: exact command-line exclusions overfit fixtures.
EXCLUSION_FIELDS = ("ParentImage", "OriginalFileName", "Company", "Product", "ParentCommandLine", "User", "Image")
_PATH_FIELDS = frozenset({"Image", "ParentImage"})
_TEXT_FIELDS = frozenset({"CommandLine", "ParentCommandLine"})
_MAX_EXCLUSION_VALUES = 8
_MAX_MUTATIONS = 32


def _candidate(
    rule: Rule, n: int, family: Family, kind: str, patch: object, *, evidence: tuple[str, ...] = ()
) -> Candidate:
    return Candidate.model_validate(
        {
            "proposal_id": f"b0-{family.value}-{n}",
            "original_sha256": rule.sha256,
            "patch_kind": kind,
            "patch": [patch],
            "reason_codes": [f"b0_{family.value}"],
            "evidence_event_ids": list(evidence[:64]),
        }
    )


def mapping_candidates(rule: Rule, mapping: FieldMapping, hyp: Hypothesis) -> list[Candidate]:
    field = hyp.fields[0]
    return [
        _candidate(
            rule,
            i,
            Family.MAPPING,
            "mapping",
            MappingPatch(sigma_field=field, from_field=mapping.target(field), to_field=alt),
        )
        for i, alt in enumerate(hyp.alternatives, 1)
    ]


def _values(dataset: Dataset, ids: frozenset[str], index_field: str) -> set[str]:
    return {v for e in dataset.events if e.event_id in ids and isinstance(v := lookup(e.data, index_field), str)}


def noise_candidates(rule: Rule, mapping: FieldMapping, dataset: Dataset, matched: frozenset[str]) -> list[Candidate]:
    """Exclude benign matches by a context value never seen on malicious events."""
    fp_ids = matched & dataset.ids("benign")
    malicious = dataset.ids("malicious")
    scored = []
    for rank, field in enumerate(EXCLUSION_FIELDS):
        target = mapping.target(field)
        fp_values = _values(dataset, fp_ids, target)
        bad_values = {v.lower() for v in _values(dataset, malicious, target)}
        if not fp_values or len(fp_values) > _MAX_EXCLUSION_VALUES or {v.lower() for v in fp_values} & bad_values:
            continue
        covered = sum(1 for e in dataset.events if e.event_id in fp_ids and lookup(e.data, target) in fp_values)
        if any(len(v) > MAX_VALUE_CHARS for v in fp_values):
            continue
        scored.append((-covered, rank, field, tuple(sorted(sigma_escape(v) for v in fp_values))))
    out = []
    for n, (_, _, field, values) in enumerate(sorted(scored)[:MAX_CANDIDATES], 1):
        patch = AddExclusion(predicates=(PredicateSpec(field=field, modifier="equals", values=values),))
        out.append(_candidate(rule, n, Family.NOISE, "rule", patch, evidence=tuple(sorted(fp_ids))))
    return out


def condition_mutations(cond: Cond) -> Iterator[Cond]:
    """Every condition one edit away: negate or un-negate a node, or swap and/or."""
    match cond:
        case Ref():
            yield Not(cond)
        case Not(inner):
            yield inner
            yield from (Not(m) for m in condition_mutations(inner))
        case And(ops) | Or(ops):
            yield (Or if isinstance(cond, And) else And)(ops)
            yield Not(cond)
            for i, op in enumerate(ops):
                for m in condition_mutations(op):
                    yield type(cond)((*ops[:i], m, *ops[i + 1 :]))


def logic_candidates(rule: Rule) -> list[Candidate]:
    out: list[Candidate] = []
    seen = {rule.condition}
    n = 0
    for cond in condition_mutations(rule.condition):
        if cond in seen or len(out) >= _MAX_MUTATIONS:
            continue
        seen.add(cond)
        n += 1
        out.append(_candidate(rule, n, Family.LOGIC, "rule", SetCondition(condition=render_condition(cond))))
    for selection, sel in rule.selections.items():
        for p in sel.predicates:
            # set_predicate must identify one predicate, so skip fields repeated across alternative maps.
            if p.modifier != "equals" or sum(q.field == p.field for q in sel.predicates) != 1:
                continue
            if p.field in _PATH_FIELDS and not any("\\" in v for v in p.values):
                spec = PredicateSpec(field=p.field, modifier="endswith", values=tuple("\\" + v for v in p.values))
            elif p.field in _TEXT_FIELDS:
                spec = PredicateSpec(field=p.field, modifier="contains", values=p.values)
            else:
                continue
            n += 1
            out.append(
                _candidate(
                    rule, n, Family.LOGIC, "rule", SetPredicate(selection=selection, field=p.field, predicate=spec)
                )
            )
    return out


# A candidate generator: (rule, mapping, development fixtures, hypotheses, original matches) -> candidates.
Generator = Callable[[Rule, FieldMapping, Dataset, list[Hypothesis], frozenset[str]], list[Candidate]]


def generate(
    rule: Rule, mapping: FieldMapping, dataset: Dataset, hyps: list[Hypothesis], matched: frozenset[str]
) -> list[Candidate]:
    out: list[Candidate] = []
    for hyp in hyps:
        if hyp.family is Family.MAPPING:
            out += mapping_candidates(rule, mapping, hyp)
        elif hyp.family is Family.NOISE:
            out += noise_candidates(rule, mapping, dataset, matched)
        elif hyp.family is Family.LOGIC:
            out += logic_candidates(rule)
    return out
