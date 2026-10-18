# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for findings from the detection-semantics review."""

import json
import os

import pytest

from kestrix.core.errors import Reason, Rejected
from kestrix.detect import cases, workflow
from kestrix.detect.candidate import Candidate, apply
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Dataset, Event
from kestrix.detect.mapping import FieldMapping, to_lucene
from kestrix.detect.replay import score
from kestrix.detect.rule import has_wildcard, parse_rule, sigma_escape
from kestrix.detect.workflow import Inputs, policy_failures

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
MAPPING = FieldMapping("m", {"Image": "process.executable", "CommandLine": "process.command_line", "User": "user.name"})
HEADER = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"


def rule(body: str):
    return parse_rule(HEADER + body)


def reason(text: str) -> Reason:
    with pytest.raises(Rejected) as exc:
        parse_rule(HEADER + text)
    return exc.value.reason


# ---- parser semantics (findings 5, 6, 8) ----------------------------------------------------
def test_escaped_backslash_before_wildcard_is_still_a_wildcard():
    assert reason("  s: {Image: 'C:\\\\*'}\n  condition: s\n") == Reason.UNSUPPORTED_WILDCARD
    assert parse_rule(HEADER + "  s: {Image: 'a\\*b'}\n  condition: s\n")  # escaped star is literal


@pytest.mark.parametrize("raw", ["\\\\srv\\share\\upd.exe", "C:\\a*b?.exe", "trailing\\", "plain"])
def test_sigma_escape_round_trips_through_pysigma(raw):
    escaped = sigma_escape(raw)
    assert not has_wildcard(escaped)
    r = rule(f"  s: {{Image: {json.dumps(escaped)}}}\n  condition: s\n")
    assert r.selections["s"].predicates[0].values == (escaped,)


def test_selection_names_that_pysigma_reads_as_operators_are_rejected():
    assert reason("  notepad: {Image: a}\n  condition: notepad\n") == Reason.INVALID_RULE
    assert reason("  order: {Image: a}\n  condition: order\n") == Reason.INVALID_RULE


def test_duplicate_yaml_keys_are_rejected():
    assert (
        reason("  s:\n    CommandLine|contains: a\n    CommandLine|contains: b\n  condition: s\n")
        == Reason.MALFORMED_YAML
    )


# ---- candidate contract (findings 7, 8, 9) --------------------------------------------------
BASE = rule("  s:\n    Image|endswith: '\\x.exe'\n    CommandLine|contains: evil\n  condition: s\n")


def cand(*patch):
    return Candidate.model_validate(
        {"proposal_id": "p", "original_sha256": BASE.sha256, "patch_kind": "rule", "patch": list(patch)}
    )


def test_set_predicate_never_drops_sibling_predicates():
    two = rule("  s:\n    Image|endswith: '\\x.exe'\n    Image|contains: '\\Temp\\'\n  condition: s\n")
    patch = {
        "kind": "set_predicate",
        "selection": "s",
        "field": "Image",
        "predicate": {"field": "Image", "modifier": "endswith", "values": ["\\y.exe"]},
    }
    c = Candidate.model_validate(
        {"proposal_id": "p", "original_sha256": two.sha256, "patch_kind": "rule", "patch": [patch]}
    )
    with pytest.raises(Rejected, match="exactly one"):
        apply(two, MAPPING, c)


def test_two_exclusions_both_survive_and_count_their_predicates():
    ex = lambda v: {"kind": "add_exclusion", "predicates": [{"field": "User", "modifier": "equals", "values": [v]}]}  # noqa: E731
    with pytest.raises(Rejected, match="AST edits"):  # 2 + 2 nodes exceeds the budget of 3
        apply(BASE, MAPPING, cand(ex("A"), ex("B")))
    new_rule, _ = apply(BASE, MAPPING, cand(ex("A")))
    assert set(new_rule.selections) == {"s", "cg_filter_1"}


def test_exclusion_with_duplicate_field_modifier_is_rejected():
    patch = {
        "kind": "add_exclusion",
        "predicates": [
            {"field": "User", "modifier": "equals", "values": ["A"]},
            {"field": "User", "modifier": "equals", "values": ["B"]},
        ],
    }
    with pytest.raises(Rejected, match="once"):
        apply(BASE, MAPPING, cand(patch))


# ---- acceptance policy (finding 1) ------------------------------------------------------------
def _ds(rows):
    return Dataset("d", tuple(Event(e, lab, sc, {}) for e, lab, sc in rows), "0" * 64)


def test_unscenarioed_attacks_are_mandatory():
    ds = _ds([("m1", "malicious", None), ("m2", "malicious", None), ("b1", "benign", None)])
    original = score(BASE, MAPPING, ds, "q", frozenset({"m1", "m2", "b1"}))
    always_false = score(BASE, MAPPING, ds, "q", frozenset())
    failures = policy_failures(always_false, original, 0, True)
    assert {"mandatory_scenario_missed", "malicious_events_lost"} <= set(failures)


def test_partial_loss_within_a_scenario_fails():
    ds = _ds([("m1", "malicious", "S"), ("m2", "malicious", "S"), ("b1", "benign", None)])
    original = score(BASE, MAPPING, ds, "q", frozenset({"m1", "m2", "b1"}))
    partial = score(BASE, MAPPING, ds, "q", frozenset({"m1"}))
    assert "malicious_events_lost" in policy_failures(partial, original, 0, True)


def test_suite_without_attacks_cannot_validate():
    ds = _ds([("b1", "benign", None)])
    r = score(BASE, MAPPING, ds, "q", frozenset())
    assert "no_attack_scenarios_in_suite" in policy_failures(r, r, 0, False)


def test_errored_replay_reports_no_counts():
    ds = _ds([("m1", "malicious", "S")])
    assert score(BASE, MAPPING, ds, None, frozenset(), error="engine_error: x").as_dict()["counts"] is None


# ---- workflow (findings 2, 3, 4, 11, 12) — need the engine -----------------------------------
@pytest.fixture(scope="module")
def es():
    engine = Elasticsearch(ES_URL)
    yield engine
    engine.close()


@pytest.mark.engine
def test_validation_must_be_independent_of_development(es):
    inputs = cases.inputs("c03-noise-updater-temp")
    same = Inputs(inputs.rule_text, inputs.mapping_text, inputs.dev_path, inputs.dev_path, inputs.healthy_rule_text)
    with pytest.raises(Rejected, match="must not share"):
        workflow.run(same, es)


@pytest.mark.engine
def test_selection_is_frozen_before_validation(es):
    report = workflow.run(cases.inputs("c03-noise-updater-temp"), es)
    validated = [c for c in report["candidates"] if "validation" in c]
    assert len(validated) == 1
    assert validated[0]["candidate"]["proposal_id"] == report["selected"]
    assert report["candidates"][0]["candidate"]["proposal_id"] == report["selected"]  # best on development


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


ENC_RULE = HEADER + "  s:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains: ' -enc '\n  condition: s\n"
MIN_MAP = "schema_version: 1\nname: m\nfields: {Image: process.executable, CommandLine: process.command_line}\n"


def _ps(eid, label, parent_cmd, scenario="S-enc"):
    data = {"process": {"executable": "C:\\Windows\\System32\\powershell.exe", "parent": {"command_line": parent_cmd}}}
    return {"event_id": eid, "label": label, "scenario_id": scenario if label == "malicious" else None, "data": data}


@pytest.mark.engine
@pytest.mark.parametrize("parent_cmd", ["explorer.exe", "powershell.exe -enc SQBFAFgA"])
def test_parent_fields_never_stand_in_for_missing_child_fields(es, tmp_path, parent_cmd):
    dev = _write(tmp_path, "dev.jsonl", [_ps("d1", "malicious", parent_cmd), _ps("d2", "benign", "svchost.exe")])
    val = _write(tmp_path, "val.jsonl", [_ps("v1", "malicious", parent_cmd), _ps("v2", "benign", "svchost.exe")])
    report = workflow.run(Inputs(ENC_RULE, MIN_MAP, dev, val), es)
    assert report["outcome"] == "insufficient_evidence"
    assert report["telemetry_recommendations"][0]["field"] == "CommandLine"


@pytest.mark.engine
def test_field_collected_only_on_benign_events_is_missing_telemetry(es, tmp_path):
    def ev(eid, label, cmd=None):
        proc = {"executable": "C:\\Windows\\System32\\powershell.exe"}
        if cmd:
            proc["command_line"] = cmd
        return {
            "event_id": eid,
            "label": label,
            "scenario_id": "S" if label == "malicious" else None,
            "data": {"process": proc},
        }

    dev = _write(tmp_path, "dev.jsonl", [ev("d1", "malicious"), ev("d2", "benign", "powershell.exe -File x.ps1")])
    val = _write(tmp_path, "val.jsonl", [ev("v1", "malicious"), ev("v2", "benign", "powershell.exe -File y.ps1")])
    report = workflow.run(Inputs(ENC_RULE, MIN_MAP, dev, val), es)
    assert report["outcome"] == "insufficient_evidence"
    assert report["hypotheses"][0]["reason_codes"] == ["field_absent_on_malicious_events"]


@pytest.mark.engine
def test_unc_exclusion_value_matches_the_benign_event(es, tmp_path):
    unc = "\\\\fileserver\\deploy\\updater.exe"
    rule_text = HEADER + "  s: {Image|endswith: '\\setup.exe'}\n  condition: s\n"
    mapping = (
        "schema_version: 1\nname: m\nfields: {Image: process.executable, ParentImage: process.parent.executable}\n"
    )

    def ev(eid, label, parent):
        return {
            "event_id": eid,
            "label": label,
            "scenario_id": f"S-{eid}" if label == "malicious" else None,
            "data": {"process": {"executable": "C:\\Temp\\setup.exe", "parent": {"executable": parent}}},
        }

    def rows(p):
        return [
            ev(f"{p}m1", "malicious", "C:\\Windows\\explorer.exe"),
            ev(f"{p}b1", "benign", unc),
            ev(f"{p}b2", "benign", unc),
        ]

    report = workflow.run(
        Inputs(rule_text, mapping, _write(tmp_path, "d.jsonl", rows("d")), _write(tmp_path, "v.jsonl", rows("v"))), es
    )
    assert report["outcome"] == "repaired", report.get("reason")
    assert report["original"]["validation"]["counts"]["fp"] == 2
    selected = next(c for c in report["candidates"] if c["candidate"]["proposal_id"] == report["selected"])
    assert selected["validation"]["counts"]["fp"] == 0  # the escaped UNC value excluded both benign events


@pytest.mark.engine
def test_unindexable_values_are_an_error_not_a_miss(es):
    events = [Event("e1", "malicious", "S", {"process": {"command_line": "x" * 40_000}})]
    with pytest.raises(Rejected, match="too long"), es.replay_index(events):
        pass


@pytest.mark.engine
def test_lucene_for_escaped_value_is_literal(es):
    r = rule(
        f"  s: {{ParentImage: {json.dumps(sigma_escape(chr(92) * 2 + 'srv' + chr(92) + 'a.exe'))}}}\n  condition: s\n"
    )
    q = to_lucene(r, FieldMapping("m", {"ParentImage": "p"}))
    events = [
        Event("hit", "unknown", None, {"p": "\\\\srv\\a.exe"}),
        Event("miss", "unknown", None, {"p": "\\srv\\a.exe"}),
    ]
    with es.replay_index(events) as index:
        assert es.search_ids(index, q).matched_ids == {"hit"}


def test_engine_client_ignores_proxy_environment(monkeypatch):
    """Cluster nodes set http_proxy without NO_PROXY; the local engine must not be proxied."""
    from kestrix.detect.engine import Elasticsearch

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("http_proxy", "http://proxy.invalid:3128")
    es = Elasticsearch("http://127.0.0.1:9200")
    try:
        assert es._http._mounts == {}  # no proxy transports mounted from the environment
    finally:
        es.close()
