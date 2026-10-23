# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The Bandit-gap report (``bandit-gap``) and the run-deriving helper of the cluster scripts, on synthetic data."""

import importlib.util
import json
from pathlib import Path

import pytest

from kestrixcodebench.build import build
from kestrixcodebench.common import SHARDS, Layout
from kestrixcodebench.gap import bandit_gap
from kestrixcodebench.scan import scan_shard

from .test_build import make_cvefixes, make_mined


@pytest.fixture
def scanned(tmp_path):
    make_cvefixes(tmp_path / "cvefixes.sqlite")
    make_mined(tmp_path / "vul")
    layout = Layout(tmp_path / "cb")
    build(layout, tmp_path / "cvefixes.sqlite", tmp_path / "vul")
    for shard in range(SHARDS):
        scan_shard(layout, "kestrix", "dev", shard, run="r1", code_sha="test")
    return layout


def copy_as_bandit(layout: Layout, run: str, empty: bool = False) -> None:
    target = layout.scan_dir(run, "bandit")
    target.mkdir(parents=True)
    for shard in range(SHARDS):
        source = layout.findings_file("r1", "kestrix", shard)
        (target / source.name).write_text("" if empty else source.read_text())


def test_gap_is_empty_when_both_tools_find_the_same(scanned):
    copy_as_bandit(scanned, "same")
    body = json.loads(bandit_gap(scanned, {"kestrix": "r1", "bandit": "same"}, "dev", "t").read_text())
    assert body["only_bandit"] == 0 and body["only_kestrix"] == 0 and body["both"] > 0
    assert body["by_bandit_test"] == []


def test_gap_counts_pairs_only_the_other_tool_detects(scanned):
    copy_as_bandit(scanned, "none", empty=True)
    body = json.loads(bandit_gap(scanned, {"kestrix": "r1", "bandit": "none"}, "dev", "t2").read_text())
    assert body["only_kestrix"] > 0 and body["both"] == 0 and body["only_bandit"] == 0


def test_derive_drops_the_named_rules(tmp_path):
    spec = importlib.util.spec_from_file_location("derive", Path(__file__).parents[2] / "hpc" / "codebench_derive.py")
    assert spec and spec.loader
    derive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(derive)
    source = tmp_path / "scans" / "a" / "kestrix"
    source.mkdir(parents=True)
    rows = [{"r": "py.one", "i": "x"}, {"r": "py.two", "i": "y"}, {"r": "py.two", "i": "z"}]
    (source / "shard-00.findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (source / "shard-00.report.json").write_text("{}")
    dropped = derive.derive(tmp_path, "a", "b", frozenset({"py.two"}))
    assert dropped == {"py.two": 2}
    kept = (tmp_path / "scans" / "b" / "kestrix" / "shard-00.findings.jsonl").read_text().splitlines()
    assert [json.loads(line)["r"] for line in kept] == ["py.one"]
