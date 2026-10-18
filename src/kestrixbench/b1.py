"""B1: lexical retrieval of reviewed training repairs (plan section 12).

Memory: every *train*-split case whose fault is repairable. Its repair is recovered by diffing the
impaired case against its healthy reference:

- a mapping repair: ``sigma_field -> healthy index field``;
- a rule repair: an *edit signature*, such as ``swap:And->Or``, ``drop_not:Ref`` or
  ``modifier:equals->endswith``.

For a new case, the generator scores the memory by TF-IDF cosine similarity over a description
of the rule structure and the diagnosis codes. It then proposes candidates by analogy:

- mapping patches toward the index fields that similar repairs used;
- condition or predicate edits whose signature matches the retrieved repairs, weighted by similarity.

Candidates then pass through the same contract, screening, freeze and validation as B0.
Development and test cases are never read into the memory.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from kestrix.detect.candidate import Candidate, MappingPatch, PredicateSpec, SetCondition, SetPredicate
from kestrix.detect.diagnose import Family, Hypothesis
from kestrix.detect.fixtures import Dataset, flatten
from kestrix.detect.mapping import FieldMapping, parse_mapping
from kestrix.detect.repair import Generator, condition_mutations
from kestrix.detect.rule import And, Cond, Not, Or, Rule, parse_rule, render_condition

from .evaluate import load_case

TOP_K = 5
_WIDER: tuple[Literal["endswith", "contains"], ...] = ("endswith", "contains")
MAX_PROPOSALS = 8


def edit_signature(before: Cond, after: Cond) -> str:
    """A rule-independent name for the single edit that turns ``before`` into ``after``."""
    if before == after:
        return "none"
    if isinstance(after, Not) and after.operand == before:
        return f"add_not:{type(before).__name__}"
    if isinstance(before, Not) and before.operand == after:
        return f"drop_not:{type(after).__name__}"
    if isinstance(before, Not) and isinstance(after, Not):
        return edit_signature(before.operand, after.operand)
    if isinstance(before, And | Or) and isinstance(after, And | Or) and len(before.operands) == len(after.operands):
        if type(before) is not type(after) and before.operands == after.operands:
            return f"swap:{type(before).__name__}->{type(after).__name__}"
        diffs = [i for i, (x, y) in enumerate(zip(before.operands, after.operands, strict=True)) if x != y]
        if type(before) is type(after) and len(diffs) == 1:
            return edit_signature(before.operands[diffs[0]], after.operands[diffs[0]])
    return "other"


def _predicate_signature(before: Rule, after: Rule) -> str | None:
    for name, sel in before.selections.items():
        other = after.selections.get(name)
        if other is None or other == sel:
            continue
        for p, q in zip(sel.predicates, other.predicates, strict=False):
            if p.field == q.field and p.modifier != q.modifier:
                return f"modifier:{p.modifier}->{q.modifier}"
    return None


def describe(rule: Rule, hyps: list[Hypothesis]) -> list[str]:
    """Tokens describing structure and diagnosis, never values."""
    tokens = [f"field:{f}" for f in sorted(rule.fields)]
    tokens += [f"key:{p.key}" for sel in rule.selections.values() for p in sel.predicates]
    tokens += [f"cond:{type(rule.condition).__name__}", f"selections:{min(len(rule.selections), 6)}"]
    tokens += [f"family:{h.family.value}" for h in hyps] + [f"code:{c}" for h in hyps for c in h.reason_codes]
    tokens += [f"hfield:{f}" for h in hyps for f in h.fields]
    return tokens


@dataclass(frozen=True)
class Repair:
    tokens: tuple[str, ...]
    kind: str  # "mapping" or "rule"
    signature: str  # edit signature, or "sigma_field->index_field" for mappings


def _diagnosis_tokens(rule: Rule, mapping: FieldMapping, healthy_mapping: FieldMapping) -> list[Hypothesis]:
    """Training-time stand-in for the diagnosis: the hypothesis families the fault implies."""
    drifted = [f for f in rule.fields if mapping.target(f) != healthy_mapping.target(f)]
    if drifted:
        return [Hypothesis(Family.MAPPING, ("mapped_field_absent", "similar_field_observed"), tuple(drifted))]
    return [Hypothesis(Family.LOGIC, ("malicious_missed_fields_present",))]


def build_memory(cases_root: Path) -> list[Repair]:
    memory: list[Repair] = []
    for case_dir in sorted(p for p in (cases_root / "train").glob("*") if (p / "case.yml").is_file()):
        manifest, inputs = load_case(case_dir)
        if manifest["split"] != "train" or manifest["expected"].get("outcome") != "repaired":
            continue
        rule = parse_rule(inputs.rule_text)
        mapping = parse_mapping(inputs.mapping_text)
        healthy_map = parse_mapping(inputs.healthy_mapping_text or inputs.mapping_text)
        healthy = parse_rule(inputs.healthy_rule_text or inputs.rule_text)
        tokens = tuple(describe(rule, _diagnosis_tokens(rule, mapping, healthy_map)))
        drifted = [f for f in sorted(rule.fields) if mapping.target(f) != healthy_map.target(f)]
        if drifted:
            memory += [Repair(tokens, "mapping", f"{f}->{healthy_map.target(f)}") for f in drifted]
            continue
        signature = _predicate_signature(rule, healthy) or edit_signature(rule.condition, healthy.condition)
        memory.append(Repair(tokens, "rule", signature))
    return memory


def _cosine(a: Counter[str], b: Counter[str], idf: dict[str, float]) -> float:
    dot = sum(a[t] * b[t] * idf.get(t, 0.0) ** 2 for t in a.keys() & b.keys())
    na = math.sqrt(sum((v * idf.get(t, 0.0)) ** 2 for t, v in a.items()))
    nb = math.sqrt(sum((v * idf.get(t, 0.0)) ** 2 for t, v in b.items()))
    return dot / (na * nb) if na and nb else 0.0


def generator(memory: list[Repair], top_k: int = TOP_K) -> Generator:
    n = len(memory)
    df = Counter(t for m in memory for t in set(m.tokens))
    idf = {t: math.log((1 + n) / (1 + d)) + 1 for t, d in df.items()}
    docs = [Counter(m.tokens) for m in memory]

    def propose(
        rule: Rule, mapping: FieldMapping, dataset: Dataset, hyps: list[Hypothesis], matched: frozenset[str]
    ) -> list[Candidate]:
        query = Counter(describe(rule, hyps))
        ranked = sorted(((_cosine(query, d, idf), i) for i, d in enumerate(docs)), reverse=True)[:top_k]
        votes: dict[str, float] = defaultdict(float)
        for sim, i in ranked:
            if sim > 0:
                votes[f"{memory[i].kind}|{memory[i].signature}"] += sim
        out: list[tuple[float, Candidate]] = []
        observed = {name for e in dataset.events for name, _ in flatten(e.data)}
        for h in hyps:
            if h.family is not Family.MAPPING:
                continue
            for field in h.fields:
                for key, weight in votes.items():
                    kind, sig = key.split("|", 1)
                    src, _, target = sig.partition("->")
                    if kind == "mapping" and src == field and target in observed and target != mapping.target(field):
                        _add(
                            out,
                            weight,
                            rule,
                            "mapping",
                            partial(MappingPatch, sigma_field=field, from_field=mapping.target(field), to_field=target),
                        )
        if any(h.family is Family.LOGIC for h in hyps):
            for cond in condition_mutations(rule.condition):
                weight = votes.get(f"rule|{edit_signature(rule.condition, cond)}", 0.0)
                if weight:
                    _add(out, weight, rule, "rule", partial(SetCondition, condition=render_condition(cond)))
            for name, sel in rule.selections.items():
                for p in sel.predicates:
                    if p.modifier != "equals" or sum(q.field == p.field for q in sel.predicates) != 1:
                        continue
                    for modifier in _WIDER:
                        weight = votes.get(f"rule|modifier:equals->{modifier}", 0.0)
                        if weight:
                            values = tuple("\\" + v for v in p.values) if modifier == "endswith" else p.values
                            _add(
                                out,
                                weight,
                                rule,
                                "rule",
                                partial(_set_predicate, name, p.field, modifier, values),
                            )
        out.sort(key=lambda x: -x[0])
        return [c for _, c in out[:MAX_PROPOSALS]]

    return propose


def _set_predicate(
    selection: str, field: str, modifier: Literal["endswith", "contains"], values: tuple[str, ...]
) -> SetPredicate:
    return SetPredicate(
        selection=selection, field=field, predicate=PredicateSpec(field=field, modifier=modifier, values=values)
    )


def _add(out: list[tuple[float, Candidate]], weight: float, rule: Rule, kind: str, make: Callable[[], object]) -> None:
    """Append a proposal, skipping any the candidate contract rejects (e.g. more than 8 values or an
    over-long condition) instead of failing the whole case."""
    try:
        out.append((weight, _cand(rule, kind, make(), len(out))))
    except ValidationError:
        return


def _cand(rule: Rule, kind: str, patch: object, n: int) -> Candidate:
    return Candidate.model_validate(
        {
            "proposal_id": f"b1-{kind}-{n + 1}",
            "original_sha256": rule.sha256,
            "patch_kind": kind,
            "patch": [patch],
            "reason_codes": ["b1_retrieval"],
            "model_revision": "b1-lexical-tfidf",
        }
    )
