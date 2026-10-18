# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Supervised fine-tuning examples for M1 (plan section 12, "Training examples").

Each example pairs the exact B2 prompt for an impaired case with its reference repair:

- the input is the B2 prompt. The diagnosis behind it comes from replaying the original rule on the
  case's development events, as the workflow does.
- the target is the repair that restores the healthy reference, recovered by diffing the impaired
  case against it:
  - a mapping patch;
  - a ``set_condition`` with the healthy condition;
  - a ``set_predicate`` with the healthy predicate.
- missing-telemetry and healthy cases target ``{"candidates": []}``, so abstention is learned too.

The function reads only the split it is given. M1 trains on ``train`` and uses ``development``
for evaluation loss; it never reads ``test``. Prompts hold no event values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kestrix.core.errors import Rejected
from kestrix.detect.candidate import MAX_AST_EDITS, Candidate, apply
from kestrix.detect.diagnose import hypotheses
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import load_dataset, profile
from kestrix.detect.mapping import FieldMapping, parse_mapping
from kestrix.detect.replay import Replayer
from kestrix.detect.rule import Rule, parse_rule, render_condition

from .b2 import build_prompt
from .evaluate import load_case


def reference_repair(
    rule: Rule, mapping: FieldMapping, healthy: Rule, healthy_map: FieldMapping
) -> dict[str, Any] | None:
    """The reference candidate, kept only when the real candidate contract accepts it and applying it
    reproduces the healthy reference. A training target the contract would refuse would teach M1
    to propose repairs that can never pass."""
    target = _reference_ops(rule, mapping, healthy, healthy_map)
    if target is None or not target["candidates"]:
        return target
    try:
        cand = Candidate.model_validate(
            {"proposal_id": "reference", "original_sha256": rule.sha256, **target["candidates"][0]}
        )
        new_rule, new_map = apply(rule, mapping, cand)
    except (Rejected, ValidationError):
        return None
    restored = (
        all(new_map.target(f) == healthy_map.target(f) for f in rule.fields)
        if cand.patch_kind == "mapping"
        else new_rule.selections == healthy.selections and new_rule.condition == healthy.condition
    )
    return target if restored else None


def _reference_ops(
    rule: Rule, mapping: FieldMapping, healthy: Rule, healthy_map: FieldMapping
) -> dict[str, Any] | None:
    """The candidate that turns the impaired case back into its healthy reference, or None when the
    fix cannot be written as candidate operations within the contract. That happens for some
    natural fixes, such as an added or removed selection, a reshaped selection or more than three
    edits."""
    drifted = sorted(f for f in rule.fields if mapping.target(f) != healthy_map.target(f))
    if drifted:
        patch = [
            {"kind": "mapping", "sigma_field": f, "from_field": mapping.target(f), "to_field": healthy_map.target(f)}
            for f in drifted
        ]
        return (
            {"candidates": [{"patch_kind": "mapping", "patch": patch[:MAX_AST_EDITS]}]}
            if len(patch) <= MAX_AST_EDITS
            else None
        )
    if rule.selections.keys() != healthy.selections.keys():
        return None
    ops: list[dict[str, object]] = []
    if rule.condition != healthy.condition:
        ops.append({"kind": "set_condition", "condition": render_condition(healthy.condition)})
    for name, sel in rule.selections.items():
        target = healthy.selections[name]
        if sel == target:
            continue
        shape = [[p.field for p in b] for b in sel.branches]
        if shape != [[q.field for q in b] for b in target.branches]:
            return None  # fields or branches changed: not a set_predicate edit
        fields = [p.field for p in sel.predicates]
        for p, q in zip(sel.predicates, target.predicates, strict=True):
            if p == q:
                continue
            if fields.count(p.field) != 1 or len(q.values) > 8:
                return None  # set_predicate must name one predicate and carry at most 8 values
            spec = {"field": q.field, "modifier": q.modifier, "values": list(q.values), "match_all": q.match_all}
            ops.append({"kind": "set_predicate", "selection": name, "field": p.field, "predicate": spec})
    if not ops or len(ops) > MAX_AST_EDITS:
        return None if ops else {"candidates": []}
    return {"candidates": [{"patch_kind": "rule", "patch": ops}]}


def example(case_dir: Path, es: Elasticsearch) -> dict[str, Any] | None:
    """One training example, or None when the reference fix is outside the candidate contract."""
    manifest, inputs = load_case(case_dir)
    rule, mapping = parse_rule(inputs.rule_text), parse_mapping(inputs.mapping_text)
    healthy = parse_rule(inputs.healthy_rule_text or inputs.rule_text)
    healthy_map = parse_mapping(inputs.healthy_mapping_text or inputs.mapping_text)
    dev = load_dataset(inputs.dev_path)
    with es.replay_index(dev.events) as index:
        original = Replayer(es, index, dev).run(rule, mapping)
    hyps = hypotheses(rule, mapping, profile(dev.events), dev, original)
    target = (
        reference_repair(rule, mapping, healthy, healthy_map)
        if manifest["expected"]["outcome"] == "repaired"
        else {"candidates": []}
    )
    if target is None:
        return None
    return {
        "case_id": manifest["case_id"],
        "root_id": manifest["root_id"],
        "kind": manifest["fault"]["kind"],
        "prompt": build_prompt(rule, mapping, dev, hyps, original.matched_ids),
        "completion": json.dumps(target, separators=(",", ":")),
    }


def build(cases_root: Path, split: str, es: Elasticsearch) -> tuple[list[dict[str, Any]], int]:
    """Examples for one split, and how many cases were skipped as not expressible in the contract."""
    if split == "test":
        raise ValueError("SFT never reads the locked test split")
    dirs = sorted(p for p in (cases_root / split).glob("*") if (p / "case.yml").is_file())
    rows = [example(d, es) for d in dirs]
    kept = [r for r in rows if r is not None]
    return kept, len(rows) - len(kept)
