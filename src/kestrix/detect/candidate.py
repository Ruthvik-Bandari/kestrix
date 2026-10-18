"""Structured repair candidate envelope and bounded patch application (section 9).

A candidate may change only selection values or modifiers, the condition, an added
contextual exclusion, or one mapping entry. Selections may hold several alternative field maps
(ADR 0002); a predicate edit must still identify exactly one predicate. Applying it re-parses the patched rule so
every candidate passes the same validator as an imported rule.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..core.errors import Reason, Rejected
from .mapping import INDEX_FIELD, FieldMapping
from .rule import And, Cond, Not, Or, Predicate, Ref, Rule, Selection, condition_refs, parse_condition, parse_rule

MAX_CANDIDATES = 4
MAX_AST_EDITS = 3


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PredicateSpec(_Strict):
    field: str
    modifier: Literal["equals", "contains", "startswith", "endswith"]
    values: tuple[str, ...] = Field(min_length=1, max_length=8)
    match_all: bool = False

    @model_validator(mode="after")
    def _all_needs_a_string_modifier(self) -> PredicateSpec:
        if self.match_all and self.modifier == "equals":
            raise ValueError("match_all applies only to contains, startswith or endswith")
        return self

    def build(self) -> Predicate:
        return Predicate(self.field, self.modifier, self.values, self.match_all)


class MappingPatch(_Strict):
    kind: Literal["mapping"] = "mapping"
    sigma_field: str
    from_field: str
    to_field: str


class AddExclusion(_Strict):
    kind: Literal["add_exclusion"] = "add_exclusion"
    predicates: tuple[PredicateSpec, ...] = Field(min_length=1, max_length=3)


class SetPredicate(_Strict):
    kind: Literal["set_predicate"] = "set_predicate"
    selection: str
    field: str
    predicate: PredicateSpec


class SetCondition(_Strict):
    kind: Literal["set_condition"] = "set_condition"
    condition: str = Field(max_length=1024)


Patch = Annotated[MappingPatch | AddExclusion | SetPredicate | SetCondition, Field(discriminator="kind")]


class Candidate(_Strict):
    schema_version: Literal[1] = 1
    proposal_id: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_kind: Literal["rule", "mapping"]
    patch: tuple[Patch, ...] = Field(min_length=1, max_length=MAX_AST_EDITS)
    reason_codes: tuple[str, ...] = ()
    evidence_event_ids: tuple[str, ...] = Field(default=(), max_length=64)
    assumptions: tuple[str, ...] = ()
    model_revision: str = "deterministic-b0"
    prompt_sha256: str | None = None


def condition_edits(a: Cond, b: Cond) -> int:
    """Approximate AST edit count between two conditions."""
    if a == b:
        return 0
    match a, b:
        case Ref(), Ref():
            return 1
        case Not(x), Not(y):
            return condition_edits(x, y)
        case Not(x), _ if x == b:
            return 1
        case _, Not(y) if y == a:
            return 1
        case ((And(xs) | Or(xs)), (And(ys) | Or(ys))) if len(xs) == len(ys):
            return (type(a) is not type(b)) + sum(condition_edits(x, y) for x, y in zip(xs, ys, strict=True))
    return _size(a) + _size(b)


def _size(c: Cond) -> int:
    match c:
        case Ref():
            return 1
        case Not(x):
            return 1 + _size(x)
        case And(xs) | Or(xs):
            return 1 + sum(_size(x) for x in xs)
    raise TypeError(c)


def _exclusion_name(selections: dict[str, Selection]) -> str:
    n = 1
    while f"cg_filter_{n}" in selections:
        n += 1
    return f"cg_filter_{n}"


def apply(rule: Rule, mapping: FieldMapping, cand: Candidate) -> tuple[Rule, FieldMapping]:
    """Apply a candidate to immutable copies; reject anything outside the repair contract."""
    if cand.original_sha256 != rule.sha256:
        raise Rejected(Reason.INVALID_CANDIDATE, "candidate targets a different rule version")
    mapping_ops = [op for op in cand.patch if isinstance(op, MappingPatch)]
    if (cand.patch_kind == "mapping") != (len(mapping_ops) == len(cand.patch)) or (
        cand.patch_kind == "rule" and mapping_ops
    ):
        raise Rejected(Reason.INVALID_CANDIDATE, "mapping candidates hold only mapping patches; rule candidates none")
    selections = dict(rule.selections)
    condition = rule.condition
    new_mapping = mapping
    edits = 0
    for op in cand.patch:
        match op:
            case MappingPatch():
                if op.sigma_field not in rule.fields or not INDEX_FIELD.fullmatch(op.to_field):
                    raise Rejected(Reason.INVALID_CANDIDATE, "mapping patch must target a field the rule uses")
                if mapping.target(op.sigma_field) != op.from_field:
                    raise Rejected(Reason.INVALID_CANDIDATE, "mapping patch from_field does not match current mapping")
                new_mapping = new_mapping.with_field(op.sigma_field, op.to_field)
                edits += 1
            case AddExclusion():
                keys = [(p.field, p.modifier) for p in op.predicates]
                if len(set(keys)) != len(keys):
                    raise Rejected(Reason.INVALID_CANDIDATE, "an exclusion may test each field/modifier once")
                name = _exclusion_name(selections)
                selections[name] = Selection.of(*(p.build() for p in op.predicates))
                condition = And((condition, Not(Ref(name))))
                edits += 1 + len(op.predicates)  # the negated reference plus each new predicate
            case SetPredicate():
                sel = selections.get(op.selection)
                targets = [p for p in sel.predicates if p.field == op.field] if sel else []
                if sel is None or op.field != op.predicate.field or len(targets) != 1:
                    raise Rejected(
                        Reason.INVALID_CANDIDATE,
                        "set_predicate must target exactly one existing predicate on that field",
                    )
                old, new = targets[0], op.predicate.build()
                selections[op.selection] = Selection(
                    tuple(tuple(new if p is old else p for p in branch) for branch in sel.branches)
                )
                edits += (old.modifier != new.modifier) + (old.values != new.values) + (old.match_all != new.match_all)
            case SetCondition():
                new_cond = parse_condition(op.condition, list(rule.selections))
                if condition_refs(new_cond) != condition_refs(rule.condition):
                    raise Rejected(Reason.INVALID_CANDIDATE, "condition must keep every original selection")
                edits += condition_edits(condition, new_cond)
                condition = new_cond
    if edits > MAX_AST_EDITS:
        raise Rejected(Reason.INVALID_CANDIDATE, f"{edits} AST edits exceeds {MAX_AST_EDITS}")
    if cand.patch_kind == "mapping":
        return rule, new_mapping
    return parse_rule(replace(rule, selections=selections, condition=condition).to_yaml()), mapping
