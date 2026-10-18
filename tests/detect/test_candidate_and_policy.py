# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from kestrix.core.errors import Reason, Rejected
from kestrix.detect.candidate import Candidate, apply, condition_edits
from kestrix.detect.fixtures import Dataset, Event, lookup, profile
from kestrix.detect.mapping import FieldMapping, parse_mapping, to_lucene
from kestrix.detect.replay import score
from kestrix.detect.rule import Ref, parse_condition, parse_rule, render_condition
from kestrix.detect.workflow import policy_failures

RULE = parse_rule("""
title: t
logsource: {category: process_creation, product: windows}
detection:
  a: {Image|endswith: '\\x.exe'}
  b: {CommandLine|contains: 'evil'}
  condition: a and b
""")
MAPPING = FieldMapping("m", {"Image": "process.executable", "CommandLine": "process.command_line"})


def cand(*patch, kind="rule"):
    return Candidate.model_validate(
        {"proposal_id": "p1", "original_sha256": RULE.sha256, "patch_kind": kind, "patch": list(patch)}
    )


def test_condition_change_keeps_all_selections():
    new_rule, _ = apply(RULE, MAPPING, cand({"kind": "set_condition", "condition": "a or b"}))
    assert new_rule.condition == parse_condition("a or b")
    with pytest.raises(Rejected) as exc:
        apply(RULE, MAPPING, cand({"kind": "set_condition", "condition": "a"}))
    assert exc.value.reason is Reason.INVALID_CANDIDATE


def test_exclusion_appends_negated_selection():
    patch = {"kind": "add_exclusion", "predicates": [{"field": "User", "modifier": "equals", "values": ["SYSTEM"]}]}
    new_rule, _ = apply(RULE, MAPPING, cand(patch))
    assert "cg_filter_1" in new_rule.selections
    assert "not cg_filter_1" in new_rule.to_yaml()


@pytest.mark.parametrize(
    "patch",
    [
        {"kind": "add_exclusion", "predicates": [{"field": "NotAField", "modifier": "equals", "values": ["x"]}]},
        {
            "kind": "set_predicate",
            "selection": "a",
            "field": "User",
            "predicate": {"field": "User", "modifier": "equals", "values": ["x"]},
        },
        {"kind": "set_condition", "condition": "a and b | count() > 1"},
    ],
)
def test_rejects_out_of_contract_patches(patch):
    with pytest.raises(Rejected):
        apply(RULE, MAPPING, cand(patch))


def test_rejects_stale_or_mixed_candidates():
    stale = Candidate.model_validate(
        {
            "proposal_id": "p",
            "original_sha256": "0" * 64,
            "patch_kind": "rule",
            "patch": [{"kind": "set_condition", "condition": "a or b"}],
        }
    )
    with pytest.raises(Rejected):
        apply(RULE, MAPPING, stale)
    mixed = cand(
        {"kind": "mapping", "sigma_field": "Image", "from_field": "process.executable", "to_field": "x"},
        {"kind": "set_condition", "condition": "a or b"},
        kind="mapping",
    )
    with pytest.raises(Rejected):
        apply(RULE, MAPPING, mixed)


def test_edit_budget_enforced():
    excessive = cand(
        {"kind": "set_condition", "condition": "not a or not b"},
        {"kind": "add_exclusion", "predicates": [{"field": "User", "modifier": "equals", "values": ["x"]}]},
    )
    with pytest.raises(Rejected, match="AST edits"):
        apply(RULE, MAPPING, excessive)
    assert condition_edits(parse_condition("a and b"), parse_condition("a or b")) == 1
    assert condition_edits(Ref("a"), parse_condition("not a")) == 1


def test_mapping_patch_and_lucene():
    patched_rule, patched = apply(
        RULE,
        MAPPING,
        cand(
            {
                "kind": "mapping",
                "sigma_field": "CommandLine",
                "from_field": "process.command_line",
                "to_field": "proc.args",
            },
            kind="mapping",
        ),
    )
    assert patched_rule is RULE
    assert patched.sha256 != MAPPING.sha256
    assert "proc.args" in to_lucene(RULE, patched)
    assert to_lucene(RULE, MAPPING) == to_lucene(RULE, MAPPING)  # re-parsing makes conversion repeatable


def test_mapping_validation():
    with pytest.raises(Rejected):
        parse_mapping("schema_version: 1\nname: x\nfields: {Bogus: a.b}\n")
    with pytest.raises(Rejected):
        parse_mapping("schema_version: 1\nname: x\nfields: {Image: 'bad field!'}\n")


def _dataset(labels):
    events = tuple(Event(f"e{i}", lab, sc, {"process": {"executable": "x"}}) for i, (lab, sc) in enumerate(labels))
    return Dataset("d", events, "0" * 64)


DS = _dataset([("malicious", "S1"), ("malicious", "S2"), ("benign", None), ("benign", None), ("unknown", None)])


def result(matched, error=None):
    return score(RULE, MAPPING, DS, "q", frozenset(matched), error=error)


def test_scoring_counts():
    r = result({"e0", "e2", "e4"})
    assert (r.tp, r.fp, r.fn, r.tn, r.unknown_matched) == (1, 1, 1, 1, 1)
    assert r.scenarios_detected == {"S1"}


def test_negative_controls_fail_policy():
    original = result({"e0", "e1", "e2"})
    always_true = result({"e0", "e1", "e2", "e3", "e4"})
    always_false = result(set())
    overfit = result({"e0"})  # drops a scenario the original caught
    assert "benign_matches_above_baseline" in policy_failures(always_true, original, 0, True)
    assert "mandatory_scenario_missed" in policy_failures(always_false, original, 0, True)
    assert "preservation_loss" in policy_failures(overfit, original, 0, True)
    assert policy_failures(result(set(), error="engine_error: boom"), original, 0, True) == ["replay_error"]
    assert policy_failures(result({"e0", "e1"}), original, 0, True) == []


def test_profile_and_lookup():
    events = [
        Event("a", "benign", None, {"process": {"command_line": "x", "pid": 4}, "flat.key": "y"}),
        Event("b", "benign", None, {"process": {"command_line": None}}),
    ]
    prof = profile(events)
    assert prof.presence("process.command_line") == 1
    assert prof.fields["process.command_line"].null == 1
    assert prof.presence("missing.field") == 0
    assert lookup(events[0].data, "flat.key") == "y"
    assert lookup(events[0].data, "process.pid") == 4
    json.dumps(prof.as_dict())


MULTI = """
title: multi
logsource: {category: process_creation, product: windows}
detection:
  sel:
    - Image: 'certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  cli:
    CommandLine|contains|all: ['-urlcache', 'http']
  condition: 1 of sel* and cli
"""


def test_set_predicate_reaches_into_alternative_maps():
    from kestrix.detect.candidate import Candidate, apply
    from kestrix.detect.mapping import FieldMapping

    rule = parse_rule(MULTI)
    cand = Candidate.model_validate(
        {
            "proposal_id": "p",
            "original_sha256": rule.sha256,
            "patch_kind": "rule",
            "patch": [
                {
                    "kind": "set_predicate",
                    "selection": "sel",
                    "field": "Image",
                    "predicate": {"field": "Image", "modifier": "endswith", "values": ["\\certutil.exe"]},
                },
                {
                    "kind": "set_predicate",
                    "selection": "cli",
                    "field": "CommandLine",
                    "predicate": {"field": "CommandLine", "modifier": "contains", "values": ["-urlcache", "http"]},
                },
            ],
        }
    )
    new_rule, _ = apply(rule, FieldMapping("m", {}), cand)
    sel = new_rule.selections["sel"]
    assert len(sel.branches) == 2
    assert sel.predicates[0].key == "Image|endswith"
    assert sel.predicates[1].key == "OriginalFileName"
    assert new_rule.selections["cli"].predicates[0].match_all is False  # dropping |all is one counted edit


def test_repeated_field_across_maps_is_not_a_single_target():
    from kestrix.detect.repair import logic_candidates

    rule = parse_rule(MULTI.replace("OriginalFileName: 'CertUtil.exe'", "Image: 'urlcache.exe'"))
    assert not [c for c in logic_candidates(rule) if c.patch[0].kind == "set_predicate"]


def test_quantifier_and_or_swap_is_one_edit():
    """Review finding: '1 of' -> 'all of' must fit the edit budget (it counted 15 before)."""
    from kestrix.detect.candidate import apply
    from kestrix.detect.mapping import FieldMapping
    from kestrix.detect.repair import logic_candidates

    rule = parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
        "  sel_a: {Image|endswith: '\\\\a.exe'}\n  sel_b: {CommandLine|contains: x}\n"
        "  filter_a: {User: s}\n  filter_b: {Company: c}\n"
        "  condition: 1 of sel_* and not 1 of filter_*\n"
    )
    applied = []
    for cand in logic_candidates(rule):
        if cand.patch[0].kind == "set_condition":
            new_rule, _ = apply(rule, FieldMapping("m", {}), cand)  # none may exceed the budget
            applied.append(render_condition(new_rule.condition))
    assert "(sel_a and sel_b) and not (filter_a or filter_b)" in applied


def test_match_all_requires_a_string_modifier():
    from pydantic import ValidationError

    from kestrix.detect.candidate import PredicateSpec

    with pytest.raises(ValidationError):
        PredicateSpec(field="Image", modifier="equals", values=("a",), match_all=True)
