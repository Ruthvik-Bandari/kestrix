import json
import os
import shutil

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrixbench.evaluate import bootstrap, run_cases, score, summarize

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")


def _manifest(kind, expected, validation=True, root="r1"):
    return {
        "case_id": f"{root}-{kind}",
        "root_id": root,
        "split": "development",
        "fault": {"kind": kind},
        "expected": expected,
        "validation": validation,
    }


MAPPING = {"outcome": "repaired", "family": "mapping", "patch_kind": "mapping"}


@pytest.mark.parametrize(
    ("expected", "report", "success", "wrong"),
    [
        (MAPPING, {"outcome": "repaired", "provisional": False, "artifact": {"kind": "mapping"}}, True, False),
        (MAPPING, {"outcome": "repaired", "provisional": True, "artifact": {"kind": "mapping"}}, False, False),
        (MAPPING, {"outcome": "repaired", "provisional": False, "artifact": {"kind": "rule"}}, False, True),
        (MAPPING, {"outcome": "abstained"}, False, False),
        ({"outcome": "insufficient_evidence"}, {"outcome": "insufficient_evidence"}, True, False),
        ({"outcome": "insufficient_evidence"}, {"outcome": "repaired", "artifact": {"kind": "rule"}}, False, True),
        ({"outcome": "unchanged"}, {"outcome": "unchanged"}, True, False),
        ({"outcome": "unchanged"}, {"outcome": "repaired", "artifact": {"kind": "rule"}}, False, True),
    ],
)
def test_scoring_rules(expected, report, success, wrong):
    row = score(_manifest("x", expected), report)
    assert (row["success"], row["wrong_change"]) == (success, wrong)


def test_engine_errors_are_failures_not_passes():
    row = score(_manifest("healthy", {"outcome": "unchanged"}), None, "engine_unavailable: down")
    assert (row["outcome"], row["success"], row["error"]) == ("error", False, "engine_unavailable: down")


def test_bootstrap_resamples_roots_and_summary_keeps_failures_in_denominator():
    rows = [
        score(
            _manifest("a", {"outcome": "unchanged"}, root=f"r{i}"), {"outcome": "unchanged" if i % 2 else "abstained"}
        )
        for i in range(10)
    ]
    ci = bootstrap(rows, "success", seed=1, reps=500)
    assert ci is not None and 0.0 <= ci[0] <= 0.5 <= ci[1] <= 1.0
    assert bootstrap(rows[:1], "success") is None  # one root has no between-root variation
    overall = summarize(rows)["overall"]
    assert (overall["cases"], overall["success_rate"], overall["abstention_rate"]) == (10, 0.5, 0.5)


@pytest.mark.engine
def test_b0_runs_generated_cases_and_skips_locked_test(tmp_path):
    from kestrixbench.evaluate import SYSTEMS
    from kestrixbench.variants import build
    from tests.bench.test_variants import make_root, split_manifest

    data = make_root(tmp_path)
    es = Elasticsearch(ES_URL)
    try:
        build(data, split_manifest(), {"per_rule": {}}, benign=set(), es=es, seed="s")
        cases = data / "benchmark/cases"
        shutil.copytree(cases / "development", cases / "test")  # a locked split that must stay unread
        for case_yml in (cases / "test").glob("*/case.yml"):
            case_yml.write_text(case_yml.read_text().replace("split: development", "split: test"))
        rows = run_cases(cases, SYSTEMS["b0"](cases), es)
        assert {r["split"] for r in rows} == {"development"}
        by_kind = {r["kind"]: r for r in rows}
        assert by_kind["healthy"]["outcome"] == "unchanged" and by_kind["healthy"]["success"]
        assert by_kind["mapping"]["success"]
        assert by_kind["missing_telemetry"]["outcome"] == "insufficient_evidence"
        assert all(r["error"] is None for r in rows)
        assert "certutil" not in json.dumps(rows)
        assert {r["split"] for r in run_cases(cases, SYSTEMS["b0"](cases), es, locked=True)} == {"development", "test"}
    finally:
        es.close()


def test_split_mismatch_is_refused(tmp_path):
    case = tmp_path / "train" / "c1"
    case.mkdir(parents=True)
    (case / "case.yml").write_text("case_id: c1\nsplit: test\n")
    for name in ("rule.yml", "mapping.yml", "development.jsonl"):
        (case / name).write_text("")
    with pytest.raises(ValueError, match="folder says 'train'"):
        run_cases(tmp_path, lambda inputs, es: {}, None)  # type: ignore[arg-type]


def test_outcome_match_counts_provisional_repairs_but_success_does_not():
    report = {"outcome": "repaired", "provisional": True, "artifact": {"kind": "mapping"}}
    row = score(_manifest("mapping", MAPPING, validation=False), report)
    assert (row["success"], row["outcome_match"]) == (False, True)
    wrong_kind = {"outcome": "repaired", "provisional": True, "artifact": {"kind": "rule"}}
    assert score(_manifest("mapping", MAPPING), wrong_kind)["outcome_match"] is False


def test_weakening_repairs_do_not_count_as_outcome_matches():
    def report(fp):
        return {
            "outcome": "repaired",
            "provisional": True,
            "artifact": {"kind": "rule"},
            "selected": "c1",
            "original": {"development": {"counts": {"tp": 0, "fp": 0}}},
            "candidates": [{"candidate": {"proposal_id": "c1"}, "development": {"counts": {"tp": 1, "fp": fp}}}],
        }

    logic = {"outcome": "repaired", "family": "logic"}
    assert score(_manifest("logic", logic), report(0))["outcome_match"] is True
    row = score(_manifest("logic", logic), report(2))
    assert (row["outcome_match"], row["adds_false_alarms"]) == (False, True)


@pytest.mark.parametrize(
    "report",
    [
        {"outcome": "engine_unavailable", "reason": "connection refused"},
        {"outcome": "abstained", "reason": "original replay failed: engine_error: 500"},
        {"outcome": "abstained", "reason": "healthy reference replay failed: engine_error: 500"},
    ],
)
def test_engine_failures_are_error_rows_not_system_outcomes(report):
    row = score(_manifest("logic", {"outcome": "repaired"}), report)
    assert row["error"] and row["outcome"] == "error" and not row["success"] and not row["abstained"]


def test_a_real_abstention_is_not_an_error():
    row = score(
        _manifest("logic", {"outcome": "repaired"}), {"outcome": "abstained", "reason": "no candidate improved"}
    )
    assert row["error"] is None and row["abstained"]


def test_weakening_is_judged_against_the_healthy_reference():
    """A correct repair may match the confounders the healthy rule matches; only more than that counts."""
    report = {
        "outcome": "repaired",
        "provisional": True,
        "artifact": {"kind": "rule"},
        "selected": "c1",
        "original": {"development": {"counts": {"tp": 0, "fp": 0}}},
        "healthy_reference": {"development": {"counts": {"tp": 1, "fp": 2}}},
        "candidates": [{"candidate": {"proposal_id": "c1"}, "development": {"counts": {"tp": 1, "fp": 2}}}],
    }
    logic = {"outcome": "repaired", "family": "logic"}
    assert score(_manifest("logic", logic), report)["adds_false_alarms"] is False
    report["candidates"][0]["development"]["counts"]["fp"] = 3
    assert score(_manifest("logic", logic), report)["adds_false_alarms"] is True
