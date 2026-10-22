# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev report, error analysis, the locked test's one-time claim and the Markdown tables, on synthetic data."""

import json

import pytest

from kestrixcodebench.build import build
from kestrixcodebench.common import SHARDS, CodeBenchError, Layout
from kestrixcodebench.examples import list_examples
from kestrixcodebench.report import compare_runs, dev_report, locked_test, markdown
from kestrixcodebench.scan import scan_shard
from kestrixvul.evaluate import LockedEvalError

from .test_build import make_cvefixes, make_mined


@pytest.fixture
def built(tmp_path):
    make_cvefixes(tmp_path / "cvefixes.sqlite")
    make_mined(tmp_path / "vul")
    layout = Layout(tmp_path / "cb")
    build(layout, tmp_path / "cvefixes.sqlite", tmp_path / "vul")
    return layout


def scan_dev(layout: Layout, run: str) -> None:
    for shard in range(SHARDS):
        scan_shard(layout, "kestrix", "dev", shard, run=run, code_sha="test")


def test_dev_report_and_tables(built):
    scan_dev(built, "r1")
    out = dev_report(built, {"kestrix": "r1"}, "t", reps=50)
    body = json.loads(out.read_text())
    assert body["split"] == "dev" and body["bootstrap"]["unit"] == "repository"
    kestrix = body["tools"]["kestrix"]
    python = kestrix["subsets"]["python"]
    assert python["pairs"] == body["dev_data"]["by_language"].get("python", 0)
    assert 0 <= python["detection"]["rate"] <= 1
    assert "cmdi" in kestrix["families"]["python"]
    assert kestrix["error_analysis"]["python"]["missed_by_family"] is not None
    assert "| kestrix | python |" in markdown(body)
    # os.system with concatenation is flagged on the before file near the changed line
    assert python["detection"]["k"] > 0
    assert list_examples(built, "kestrix", "r1", "cmdi", 3) is not None


def test_dev_report_needs_a_dev_scan(built):
    with pytest.raises(CodeBenchError, match="missing"):
        dev_report(built, {"kestrix": "none"}, "t", reps=5)


def test_locked_test_runs_once_and_never_before_the_claim(built):
    scan_dev(built, "r1")
    out = locked_test(built, "unit", {"kestrix": "r1"}, "sha", reps=20)
    body = json.loads(out.read_text())
    assert body["split"] == "test" and body["tools"]["kestrix"]["subsets"]["all"]["pairs"] > 0
    claim = json.loads((built.reports / "LOCKED_EVAL.json").read_text())
    assert claim["name"] == "unit" and claim["report"] == out.name and claim["report_sha256"]
    with pytest.raises(LockedEvalError):
        locked_test(built, "again", {"kestrix": "r1"}, "sha", reps=20)


def test_locked_test_refuses_without_dev_findings(built):
    with pytest.raises(CodeBenchError, match="missing"):
        locked_test(built, "unit", {"kestrix": "never-scanned"}, "sha", reps=5)
    assert not (built.reports / "LOCKED_EVAL.json").exists()  # a failed dry run does not burn the lock


def test_compare_runs_pairs_two_scans(built):
    scan_dev(built, "r1")
    scan_dev(built, "r2")
    body = json.loads(compare_runs(built, "r1", "r2", "t", reps=20).read_text())
    python = body["subsets"]["python"]
    assert python["detection"]["delta"] == 0.0 and python["detection"]["ci95"] == [0.0, 0.0]
    assert python["alerts_per_kloc"]["delta"] == 0.0
    assert python["detection"]["k_base"] == python["detection"]["k_new"] > 0
