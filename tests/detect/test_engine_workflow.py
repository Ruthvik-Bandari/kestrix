# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests against the pinned Elasticsearch (skipped when it is not running)."""

import json
import os

import pytest
from typer.testing import CliRunner

from kestrix.detect import cases, workflow
from kestrix.detect.cli import app
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Event
from kestrix.detect.mapping import FieldMapping
from kestrix.detect.rule import parse_rule

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")

pytestmark = pytest.mark.engine


@pytest.fixture(scope="module")
def es():
    engine = Elasticsearch(ES_URL)
    yield engine
    engine.close()


@pytest.mark.parametrize("case", cases.list_cases(), ids=lambda c: c["case_id"])
def test_bundled_case_reaches_expected_outcome(es, case):
    report = workflow.run(cases.inputs(case["case_id"]), es)
    expected = case["expected"]
    assert report["outcome"] == expected["outcome"], report.get("reason")
    if "family" in expected:
        assert expected["family"] in {h["family"] for h in report["hypotheses"]}
    if "patch_kind" in expected:
        assert report["artifact"]["kind"] == expected["patch_kind"]
        assert report["provisional"] is False
    json.dumps(report)


def _events(rows):
    return [Event(f"e{i}", "unknown", None, data) for i, data in enumerate(rows)]


SEMANTICS = parse_rule("""
title: semantics
logsource: {category: process_creation, product: windows}
detection:
  sel: {Image|endswith: '\\CertUtil.EXE'}
  condition: sel
""")


def test_golden_engine_semantics(es):
    """Case-insensitive matching, missing fields and arrays behave as documented."""
    rows = [
        {"process": {"executable": "C:\\Windows\\System32\\certutil.exe"}},  # lower case matches
        {"process": {"executable": "C:\\Tools\\CERTUTIL.EXE"}},  # upper case matches
        {"process": {}},  # missing field never matches
        {"process": {"executable": ["C:\\a.exe", "C:\\b\\certutil.exe"]}},  # any array element matches
        {"process": {"executable": "C:\\certutil.exe.bak"}},  # suffix must be at the end
    ]
    mapping = FieldMapping("m", {"Image": "process.executable"})
    from kestrix.detect.mapping import to_lucene

    with es.replay_index(_events(rows)) as index:
        hits = es.search_ids(index, to_lucene(SEMANTICS, mapping)).matched_ids
    assert hits == {"e0", "e1", "e3"}


def test_negated_filter_on_missing_field_matches_everything(es):
    """Documents why mapping drift on a filter field silently disables the exclusion."""
    with es.replay_index(_events([{"a": "x"}, {"a": "y"}])) as index:
        assert es.search_ids(index, "NOT missing.field:*x*").matched_ids == {"e0", "e1"}


def test_pagination_returns_every_match(es):
    rows = [{"process": {"executable": "C:\\certutil.exe"}} for _ in range(12_000)]
    with es.replay_index(_events(rows)) as index:
        result = es.search_ids(index, "process.executable:*certutil.exe")
    assert result.total_hits == len(result.matched_ids) == 12_000


def test_cli_demo_exit_codes(tmp_path):
    runner = CliRunner()
    ok = runner.invoke(app, ["demo", "c01-mapping-drift-commandline", "--evidence-dir", str(tmp_path)])
    assert ok.exit_code == 0, ok.output
    assert "outcome: repaired" in ok.output
    assert len(list(tmp_path.glob("*.json"))) == 1
    assert runner.invoke(app, ["demo", "c05-missing-telemetry-commandline"]).exit_code == 10
    assert runner.invoke(app, ["demo", "c09-unsupported-regex"]).exit_code == 11
    assert runner.invoke(app, ["demo", "../../etc"]).exit_code == 2
