# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Impairment variants: ECS conversion, verification on the pinned engine, and case output."""

import json
import os
import stat
import sys
import zipfile

import pytest
import yaml

from kestrix.detect.engine import Elasticsearch
from kestrixbench.qc import SIGMA_REGRESSION, SIGMA_RULES, SYSMON_CHANNEL
from kestrixbench.variants import _drop, build, to_ecs

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
RID = "00000000-0000-4000-8000-0000000000aa"
RULE = f"""title: certutil download
id: {RID}
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: ['-urlcache', '-verifyctl']
  condition: selection
"""


def test_to_ecs_nests_v1_fields_and_drop_removes_one():
    data = to_ecs({"Image": "C:\\a.exe", "ParentImage": "C:\\p.exe", "Unknown": "x"})
    assert data == {
        "event": {"code": "1"},
        "process": {"executable": "C:\\a.exe", "parent": {"executable": "C:\\p.exe"}},
    }
    dropped = _drop(data, "process.parent.executable")
    assert dropped["process"] == {"executable": "C:\\a.exe", "parent": {}}
    assert data["process"]["parent"] == {"executable": "C:\\p.exe"}  # the input is not mutated


def _sysmon(image, cmd):
    return {
        "Event": {
            "System": {"EventID": 1, "Channel": SYSMON_CHANNEL},
            "EventData": {"Image": image, "CommandLine": cmd},
        }
    }


def make_root(tmp_path):
    """One root (certutil download) with two SigmaHQ positives and three OTRF background events."""
    sigma = tmp_path / "sigma"
    (sigma / SIGMA_RULES).mkdir(parents=True)
    (sigma / SIGMA_RULES / "proc_creation_win_certutil_download.yml").write_text(RULE)
    case = sigma / SIGMA_REGRESSION / "certutil"
    case.mkdir(parents=True)
    (case / "info.yml").write_text(f"rule_metadata:\n  - id: {RID}\n")
    events = [
        _sysmon("C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://h/a out"),
        _sysmon("C:\\Windows\\System32\\certutil.exe", "certutil -verifyctl -f http://h/b out"),
    ]
    (case / f"{RID}.json").write_text("\n".join(json.dumps(e) for e in events))
    archive = tmp_path / "otrf/datasets/atomic/windows/execution/host/bg.zip"
    archive.parent.mkdir(parents=True)
    rows = [
        {
            "EventID": 1,
            "Channel": SYSMON_CHANNEL,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost -k x",
        },
        {
            "EventID": 1,
            "Channel": SYSMON_CHANNEL,
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil -dump",
        },
        {"EventID": 1, "Channel": SYSMON_CHANNEL, "Image": "C:\\Tools\\x.exe", "CommandLine": "x -urlcache"},
    ]
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("bg.json", "\n".join(json.dumps(r) for r in rows))
    return tmp_path


@pytest.fixture
def root(tmp_path):
    return make_root(tmp_path)


def split_manifest():
    rule = {"id": RID, "path": f"{SIGMA_RULES}/proc_creation_win_certutil_download.yml"}
    rule["positive_event_ids"] = [f"sigma:{RID}:0", f"sigma:{RID}:1"]
    return {"splits": {"development": [{"rules": [rule]}], "reserve": []}}


@pytest.mark.engine
def test_variants_are_verified_written_privately_and_repairable(root):
    from kestrix.detect.workflow import Inputs, run

    report = {"per_rule": {RID: {"matched_event_ids": [f"sigma:{RID}:0", f"sigma:{RID}:1"]}}}
    es = Elasticsearch(ES_URL)
    try:
        result = build(root, split_manifest(), report, benign=set(), es=es, seed="s")
        assert result["cases_by_kind"] == {"healthy": 1, "logic": 1, "mapping": 1, "missing_telemetry": 1}
        assert result["cases_by_split"] == {"development": 4}
        assert result["cases_without_validation_suite"] == 0
        assert result["roots_without_variants"] == 0
        assert "certutil" not in json.dumps(result)  # counts only

        case = root / "benchmark/cases/development" / f"{RID}-mapping"
        manifest = yaml.safe_load((case / "case.yml").read_text())
        assert manifest["fault"]["kind"] == "mapping" and manifest["provenance"] == "synthetic"
        if sys.platform != "win32":
            assert stat.S_IMODE((case / "development.jsonl").stat().st_mode) == 0o600
        dev = [json.loads(x) for x in (case / "development.jsonl").read_text().splitlines()]
        val = [json.loads(x) for x in (case / "validation.jsonl").read_text().splitlines()]
        assert {e["event_id"] for e in dev}.isdisjoint({e["event_id"] for e in val})

        # The generated case runs through the shipped workflow, and B0 repairs the mapping drift.
        report_b0 = run(
            Inputs(
                rule_text=(case / "rule.yml").read_text(),
                mapping_text=(case / "mapping.yml").read_text(),
                dev_path=case / "development.jsonl",
                validation_path=case / "validation.jsonl",
                healthy_rule_text=(case / "healthy_rule.yml").read_text(),
                healthy_mapping_text=(case / "healthy_mapping.yml").read_text(),
            ),
            es,
        )
        assert report_b0["outcome"] == "repaired", report_b0.get("reason")
    finally:
        es.close()


@pytest.mark.engine
def test_negative_control_weakened_repair_fails_validation(tmp_path):
    """Plan section 9: an always-true style repair must fail validation. It catches the missed
    attack, so it passes development screening, and only the reference negatives (labeled
    benign) expose it as a false-alarm generator."""
    from kestrix.detect.candidate import Candidate
    from kestrix.detect.fixtures import Event
    from kestrix.detect.workflow import Inputs, run
    from kestrixbench.variants import HEALTHY, _jsonl, _mapping_yaml, to_ecs

    healthy = RULE
    impaired = RULE.replace("['-urlcache', '-verifyctl']", "'-urlcache'")  # misses -verifyctl downloads

    def ev(eid, label, cmd, image="C:\\Windows\\certutil.exe"):
        return Event(eid, label, "S1" if label == "malicious" else None, to_ecs({"Image": image, "CommandLine": cmd}))

    dev = [
        ev("d1", "malicious", "certutil -urlcache -f http://h/a"),
        ev("d2", "malicious", "certutil -verifyctl -f http://h/b"),
        ev("d3", "benign", "certutil -dump cert.cer"),
    ]
    val = [
        ev("v1", "malicious", "certutil -verifyctl -f http://h/c"),
        ev("v2", "benign", "certutil -hashfile x SHA256"),
        ev("v3", "benign", "certutil -encode a b"),
    ]
    (tmp_path / "dev.jsonl").write_text(_jsonl(dev))
    (tmp_path / "val.jsonl").write_text(_jsonl(val))
    inputs = Inputs(
        impaired,
        _mapping_yaml(HEALTHY),
        tmp_path / "dev.jsonl",
        tmp_path / "val.jsonl",
        healthy,
        _mapping_yaml(HEALTHY),
    )

    def weaken(rule, mapping, dataset, hyps, matched):  # "-" matches every certutil command line
        spec = {"field": "CommandLine", "modifier": "contains", "values": ["-"]}
        patch = {"kind": "set_predicate", "selection": "selection", "field": "CommandLine", "predicate": spec}
        return [
            Candidate.model_validate(
                {"proposal_id": "weaken", "original_sha256": rule.sha256, "patch_kind": "rule", "patch": [patch]}
            )
        ]

    es = Elasticsearch(ES_URL)
    try:
        report = run(inputs, es, generator=weaken)
    finally:
        es.close()
    assert report["outcome"] == "abstained", report.get("reason")
    assert "benign_matches_above_baseline" in report["reason"]
    assert report["candidates"][0]["candidate"]["proposal_id"] == "weaken"  # it did pass screening


def test_background_negatives_never_include_a_known_positive():
    from kestrixbench.variants import background_negatives, known_positives

    manifest = {"splits": {"test": [{"rules": [{"id": "t", "positive_event_ids": ["otrf:a:1"]}]}], "reserve": []}}
    excluded = known_positives(manifest, {"otrf:b:2"})
    picked = background_negatives(["otrf:a:1", "otrf:b:2", "otrf:c:3", "otrf:d:4"], {"otrf:d:4"}, excluded, "r", "s")
    assert picked == ["otrf:c:3"]  # not a test positive, not reviewed-malicious, not matched by the rule
