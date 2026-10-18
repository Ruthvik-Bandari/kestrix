# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Parser for the bounded single-event Sigma subset (plan section 5, "Version one semantics").

Supported: one process_creation/windows rule; named selections written as a field map or a
list of field maps (OR of maps); exact / contains / startswith / endswith string matching with
value lists, optionally ``|all``; and conditions built from selection names with ``and``, ``or``,
``not``, parentheses and the ``1 of`` / ``all of`` quantifiers (ADR 0002). Everything else is
rejected with a reason code before conversion.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

import yaml

from ..core.errors import Reason, Rejected
from ..core.safe_load import load_yaml

Modifier = Literal["equals", "contains", "startswith", "endswith"]
SUPPORTED_MODIFIERS: frozenset[str] = frozenset({"contains", "startswith", "endswith"})

# Sysmon EventID 1 field names accepted in version one.
PROCESS_CREATION_FIELDS: frozenset[str] = frozenset(
    {
        "Image",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonId",
        "IntegrityLevel",
        "Hashes",
        "Product",
        "Company",
        "Description",
        "FileVersion",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser",
        "ProcessId",
        "ParentProcessId",
    }
)

MAX_SELECTIONS = 32
MAX_BRANCHES = 16
MAX_VALUES = 64
MAX_VALUE_CHARS = 4096
MAX_TOTAL_VALUES = 2048
MAX_CONDITION_CHARS = 4096
MAX_CONDITION_DEPTH = 32
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_*][A-Za-z0-9_*]*|\d+|\S+)")
_PATTERN = re.compile(r"[A-Za-z_*][A-Za-z0-9_*]{0,63}")
_RESERVED = frozenset({"and", "or", "not", "of", "them", "all"})


@dataclass(frozen=True)
class Predicate:
    """``field`` matched against ``values``: any value by default, every value when ``match_all``."""

    field: str
    modifier: Modifier
    values: tuple[str, ...]
    match_all: bool = False

    @property
    def key(self) -> str:
        key = self.field if self.modifier == "equals" else f"{self.field}|{self.modifier}"
        return f"{key}|all" if self.match_all else key


@dataclass(frozen=True)
class Selection:
    """OR of branches; each branch is an AND of its predicates (a Sigma field map)."""

    branches: tuple[tuple[Predicate, ...], ...]

    @classmethod
    def of(cls, *predicates: Predicate) -> Selection:
        return cls((predicates,))

    @property
    def predicates(self) -> tuple[Predicate, ...]:
        return tuple(p for branch in self.branches for p in branch)

    def to_sigma(self) -> object:
        maps = [{p.key: list(p.values) if len(p.values) > 1 else p.values[0] for p in b} for b in self.branches]
        return maps[0] if len(maps) == 1 else maps


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    operand: Cond


@dataclass(frozen=True)
class And:
    operands: tuple[Cond, ...]


@dataclass(frozen=True)
class Or:
    operands: tuple[Cond, ...]


Cond = Ref | Not | And | Or


@dataclass(frozen=True)
class Rule:
    """Validated rule. ``sha256`` is over the exact source bytes."""

    title: str
    rule_id: str | None
    selections: dict[str, Selection]
    condition: Cond
    meta: dict[str, object]
    source: str
    sha256: str

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(p.field for sel in self.selections.values() for p in sel.predicates)

    def to_yaml(self) -> str:
        """Serialize to canonical Sigma YAML (used for patched rules)."""
        doc: dict[str, object] = {"title": self.title}
        if self.rule_id:
            doc["id"] = self.rule_id
        doc.update(self.meta)
        doc["logsource"] = {"category": "process_creation", "product": "windows"}
        detection: dict[str, object] = {}
        for name, sel in self.selections.items():
            detection[name] = sel.to_sigma()
        detection["condition"] = render_condition(self.condition)
        doc["detection"] = detection
        return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# Example: a rule titled 'Suspicious Thorntorfen Child Process' renders with every nested group in parentheses.
def render_condition(cond: Cond, parent: type | None = None) -> str:
    match cond:
        case Ref(name):
            return name
        case Not(operand):
            return f"not {render_condition(operand, Not)}"
        case And(ops) | Or(ops):
            word = " and " if isinstance(cond, And) else " or "
            text = word.join(render_condition(o, type(cond)) for o in ops)
            # Every nested group keeps its parentheses, so parse(render(c)) == c exactly. This keeps
            # quantifier groups (``1 of x*`` inside an ``and``) intact for edit counting.
            return f"({text})" if parent is not None else text
    raise TypeError(cond)


def condition_refs(cond: Cond) -> set[str]:
    match cond:
        case Ref(name):
            return {name}
        case Not(operand):
            return condition_refs(operand)
        case And(ops) | Or(ops):
            return set().union(*(condition_refs(o) for o in ops))
    raise TypeError(cond)


def _quantified(quantifier: str, target: str, names: Sequence[str] | None) -> Cond:
    """Expand ``1 of X`` / ``all of X`` to an OR / AND of the selections matching ``X``."""
    if quantifier not in ("1", "all"):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, f"only '1 of' and 'all of' are supported, not {quantifier!r}")
    if names is None:
        raise Rejected(Reason.UNSUPPORTED_CONDITION, "quantifiers need the rule's selection names")
    if target != "them" and (not _PATTERN.fullmatch(target) or target in _RESERVED):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, f"unsupported quantifier target {target!r}")
    # As in pySigma, names starting with "_" match only a pattern that itself starts with "_".
    pattern = "*" if target == "them" else target
    matched = [n for n in names if fnmatchcase(n, pattern) and (pattern.startswith("_") or not n.startswith("_"))]
    if not matched:
        raise Rejected(Reason.UNDEFINED_SELECTION, f"{quantifier} of {target} matches no selection")
    refs = tuple(Ref(n) for n in matched)
    if len(refs) == 1:
        return refs[0]
    return Or(refs) if quantifier == "1" else And(refs)


def parse_condition(text: str, names: Sequence[str] | None = None) -> Cond:
    """Recursive descent: or -> and -> not -> atom. Precedence: not > and > or.

    ``names`` are the rule's selection names in definition order; quantifiers expand against them."""
    tokens = [m.group(1) for m in _TOKEN.finditer(text)]
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise Rejected(Reason.UNSUPPORTED_CONDITION, "unexpected end of condition")
        pos += 1
        return tok

    depth = 0

    def parse_or() -> Cond:
        ops = [parse_and()]
        while peek() == "or":
            take()
            ops.append(parse_and())
        return ops[0] if len(ops) == 1 else Or(tuple(ops))

    def parse_and() -> Cond:
        ops = [parse_not()]
        while peek() == "and":
            take()
            ops.append(parse_not())
        return ops[0] if len(ops) == 1 else And(tuple(ops))

    def parse_not() -> Cond:
        if peek() == "not":
            take()
            return Not(parse_not())
        return parse_atom()

    def parse_atom() -> Cond:
        tok = take()
        if peek() == "of":
            take()
            return _quantified(tok, take(), names)
        if tok == "(":
            nonlocal depth
            depth += 1
            if depth > MAX_CONDITION_DEPTH:
                raise Rejected(Reason.UNSUPPORTED_CONDITION, f"condition nesting exceeds {MAX_CONDITION_DEPTH}")
            inner = parse_or()
            depth -= 1
            if take() != ")":
                raise Rejected(Reason.UNSUPPORTED_CONDITION, "unbalanced parentheses")
            return inner
        if not _NAME.fullmatch(tok) or tok in _RESERVED:
            raise Rejected(Reason.UNSUPPORTED_CONDITION, f"unsupported token {tok!r}")
        return Ref(tok)

    if len(text) > MAX_CONDITION_CHARS:
        raise Rejected(Reason.UNSUPPORTED_CONDITION, f"condition exceeds {MAX_CONDITION_CHARS} characters")
    if not tokens:
        raise Rejected(Reason.INVALID_RULE, "empty condition")
    result = parse_or()
    if pos != len(tokens):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, f"unsupported token {tokens[pos]!r}")
    return result


def has_wildcard(value: str) -> bool:
    """True if a Sigma string contains an unescaped ``*`` or ``?``. Sigma escapes are ``\\*``,
    ``\\?`` and ``\\\\``; any other backslash is literal."""
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            i += 2
            continue
        if value[i] in "*?":
            return True
        i += 1
    return False


def sigma_escape(raw: str) -> str:
    """Encode a raw event value as a plain Sigma string that matches it literally."""
    out = []
    for i, ch in enumerate(raw):
        if ch in "*?":
            out.append("\\" + ch)
        elif ch == "\\" and (i + 1 == len(raw) or raw[i + 1] in "*?\\"):
            out.append("\\\\")
        else:
            out.append(ch)
    return "".join(out)


def _parse_value(field: str, value: object) -> str:
    if value is None:
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: null matching is not supported in v1")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: {type(value).__name__} values are not supported")
    text = str(value)
    if not text or len(text) > MAX_VALUE_CHARS:
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: empty or oversized value")
    if has_wildcard(text):
        raise Rejected(Reason.UNSUPPORTED_WILDCARD, f"{field}: wildcard values are not supported in v1")
    return text


def _parse_selection(name: str, body: object) -> Selection:
    raw = body if isinstance(body, list) else [body]
    maps: list[dict[object, object]] = [m for m in raw if isinstance(m, dict) and m]
    if not raw or len(maps) != len(raw):
        raise Rejected(
            Reason.UNSUPPORTED_SELECTION_FORM,
            f"{name}: only non-empty field maps or lists of them are supported (no keyword selections)",
        )
    if len(maps) > MAX_BRANCHES:
        raise Rejected(Reason.UNSUPPORTED_SELECTION_FORM, f"{name}: at most {MAX_BRANCHES} alternative maps")
    return Selection(tuple(_parse_map(name, m) for m in maps))


def _parse_map(name: str, body: dict[object, object]) -> tuple[Predicate, ...]:
    preds = []
    for key, raw in body.items():
        if not isinstance(key, str):
            raise Rejected(Reason.INVALID_RULE, f"{name}: field keys must be strings")
        field, *mods = key.split("|")
        if field not in PROCESS_CREATION_FIELDS:
            raise Rejected(Reason.UNKNOWN_FIELD, f"{name}: field {field!r} is not a supported process_creation field")
        match_all = mods[1:] == ["all"]
        if len(mods) > 1 + match_all or (mods and mods[0] not in SUPPORTED_MODIFIERS):
            raise Rejected(Reason.UNSUPPORTED_MODIFIER, f"{name}: modifier {'|'.join(mods)!r} is not supported")
        items = raw if isinstance(raw, list) else [raw]
        if not items or len(items) > MAX_VALUES:
            raise Rejected(Reason.UNSUPPORTED_VALUE, f"{name}.{field}: 1..{MAX_VALUES} values required")
        values = tuple(_parse_value(field, v) for v in items)
        preds.append(Predicate(field, mods[0] if mods else "equals", values, match_all))  # type: ignore[arg-type]
    return tuple(preds)


def parse_rule(source: str) -> Rule:
    doc = load_yaml(source)
    if not isinstance(doc, dict):
        raise Rejected(Reason.INVALID_RULE, "rule must be a mapping")
    for meta_key in ("correlation", "filter", "action"):
        if meta_key in doc:
            raise Rejected(Reason.UNSUPPORTED_RULE_TYPE, f"{meta_key} rules are not supported")
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise Rejected(Reason.INVALID_RULE, "title is required")
    logsource = doc.get("logsource")
    if (
        not isinstance(logsource, dict)
        or logsource.get("category") != "process_creation"
        or logsource.get("product") != "windows"
    ):
        raise Rejected(Reason.UNSUPPORTED_LOGSOURCE, "only logsource process_creation/windows is supported")
    if set(logsource) - {"category", "product", "service", "definition"} or logsource.get("service"):
        raise Rejected(Reason.UNSUPPORTED_LOGSOURCE, "logsource service and custom keys are not supported")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise Rejected(Reason.INVALID_RULE, "detection must be a mapping")
    if "timeframe" in detection:
        raise Rejected(Reason.UNSUPPORTED_RULE_TYPE, "timeframe/aggregation is not supported")
    condition_text = detection.get("condition")
    if not isinstance(condition_text, str):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, "condition must be a single string")
    if "|" in condition_text:
        raise Rejected(Reason.UNSUPPORTED_CONDITION, "aggregation pipes are not supported")

    selections: dict[str, Selection] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        # pySigma's grammar reads a leading and/or/not as an operator even inside a longer name.
        if (
            not isinstance(name, str)
            or not _NAME.fullmatch(name)
            or name.lower().startswith(("and", "or", "not"))
            or name in _RESERVED
        ):
            raise Rejected(Reason.INVALID_RULE, f"invalid selection name {name!r}")
        selections[name] = _parse_selection(name, body)
    if not selections or len(selections) > MAX_SELECTIONS:
        raise Rejected(Reason.INVALID_RULE, f"1..{MAX_SELECTIONS} selections required")

    if sum(len(p.values) for sel in selections.values() for p in sel.predicates) > MAX_TOTAL_VALUES:
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"more than {MAX_TOTAL_VALUES} values in one rule")
    condition = parse_condition(condition_text, list(selections))
    undefined = condition_refs(condition) - selections.keys()
    if undefined:
        raise Rejected(Reason.UNDEFINED_SELECTION, f"condition references {sorted(undefined)}")

    meta = {
        k: v
        for k, v in doc.items()
        if k in ("status", "description", "author", "level", "tags", "references", "falsepositives")
    }
    rule_id = doc.get("id")
    return Rule(
        title=title,
        rule_id=str(rule_id) if rule_id is not None else None,
        selections=selections,
        condition=condition,
        meta=meta,
        source=source,
        sha256=sha256_text(source),
    )
