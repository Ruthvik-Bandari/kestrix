import json
import zipfile
from pathlib import Path

from kestrixbench.qc import SIGMA_REGRESSION, SIGMA_RULES, SYSMON_CHANNEL, qc_atomic, qc_otrf, qc_sigma

RULE = """title: {title}
id: {rid}
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '{value}'
  condition: selection
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_sigma_qc_counts_support_duplicates_and_regression(tmp_path):
    rules = tmp_path / SIGMA_RULES
    _write(
        rules / "a.yml",
        "date: 2025-12-25\n" + RULE.format(title="A", rid="00000000-0000-4000-8000-00000000000a", value="\\\\a.exe"),
    )
    _write(
        rules / "b.yml", RULE.format(title="B", rid="00000000-0000-4000-8000-00000000000b", value="\\\\a.exe")
    )  # same logic as A
    _write(rules / "c.yml", RULE.format(title="C", rid="00000000-0000-4000-8000-00000000000c", value="*wild*"))
    _write(rules / "d.yml", "title: D\na: &x 1\nb: *x\n")  # alias: refused by the strict loader
    case = tmp_path / SIGMA_REGRESSION / "a"
    _write(case / "info.yml", "rule_metadata:\n  - id: 00000000-0000-4000-8000-00000000000a\n    title: A\n")
    event = {"Event": {"System": {"EventID": 1, "Channel": SYSMON_CHANNEL}, "EventData": {"Image": "x"}}}
    _write(case / "00000000-0000-4000-8000-00000000000a.json", json.dumps(event))

    report = qc_sigma(tmp_path)
    assert report["rules_total"] == 4
    assert report["outcomes"]["supported"] == 2
    assert report["outcomes"]["unsupported:unsupported_wildcard"] == 1
    assert report["top_unsupported_causes"] == [("unsupported_wildcard: wildcard values are not supported in v1", 1)]
    assert report["missing_id"] == 0  # the alias-refused rule is counted as a load failure, not a missing id
    assert report["outcomes"]["load:yaml_alias_not_allowed"] == 1
    assert report["duplicate_detection_groups"] == [[f"{SIGMA_RULES}/a.yml", f"{SIGMA_RULES}/b.yml"]]
    assert report["regression"]["sysmon_eid1_events"] == 1
    assert report["regression"]["supported_rules_with_positive_events"] == ["00000000-0000-4000-8000-00000000000a"]
    assert report["regression"]["problems"] == []
    assert "x" not in json.dumps(report["regression"])  # no event values in reports


def test_sigma_qc_reports_missing_regression_events(tmp_path):
    (tmp_path / SIGMA_RULES).mkdir(parents=True)
    _write(tmp_path / SIGMA_REGRESSION / "z/info.yml", "rule_metadata:\n  - id: id-z\n")
    assert qc_sigma(tmp_path)["regression"]["problems"] == ["z: missing id-z.json"]


def test_otrf_qc_counts_sysmon_process_creation(tmp_path):
    meta = tmp_path / "datasets/atomic/_metadata"
    _write(
        meta / "SDWIN-1.yaml",
        "attack_mappings:\n  - technique: T1059\nfiles:\n  - link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/one.zip\n",
    )
    _write(
        meta / "SDWIN-2.yaml",
        "files:\n  - link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/gone.zip\n",
    )
    zpath = tmp_path / "datasets/atomic/windows/execution/host/one.zip"
    zpath.parent.mkdir(parents=True)
    lines = [{"EventID": 1, "Channel": SYSMON_CHANNEL}, {"EventID": 4688, "Channel": "Security"}]
    with zipfile.ZipFile(zpath, "w") as archive:
        archive.writestr("one.json", "\n".join(json.dumps(x) for x in lines))
        archive.writestr("__MACOSX/._one.json", b"\x00\x05\x16\x07 not json")
    (zpath.parent / "broken.zip").write_bytes(b"not a zip")

    report = qc_otrf(tmp_path)
    assert report["windows_metadata_files"] == 2
    assert report["records_total"] == 2
    assert report["sysmon_eid1_records"] == 1
    assert report["metadata_links_missing_zip"] == ["execution/host/gone"]
    assert report["problems"] == ["execution/host/broken: BadZipFile"]


def test_atomic_qc_counts_windows_executors(tmp_path):
    _write(
        tmp_path / "atomics/T1059/T1059.yaml",
        "atomic_tests:\n"
        "  - name: a\n    supported_platforms: [windows]\n    executor: {name: powershell}\n"
        "  - name: b\n    supported_platforms: [linux]\n    executor: {name: sh}\n",
    )
    _write(tmp_path / "atomics/T1000/T1000.yaml", "nope: 1\n")
    report = qc_atomic(tmp_path)
    assert (report["techniques"], report["tests"], report["windows_tests"]) == (1, 2, 1)
    assert report["windows_executors"] == {"powershell": 1}
    assert report["problems"] == ["T1000.yaml: missing atomic_tests list"]


def test_sigma_regression_accepts_concatenated_events(tmp_path):
    (tmp_path / SIGMA_RULES).mkdir(parents=True)
    case = tmp_path / SIGMA_REGRESSION / "m"
    _write(case / "info.yml", "rule_metadata:\n  - id: id-m\n")
    event = {"Event": {"System": {"EventID": 1, "Channel": SYSMON_CHANNEL}, "EventData": {}}}
    _write(case / "id-m.json", json.dumps(event, indent=2) + "\n" + json.dumps(event, indent=2) + "\n")
    regression = qc_sigma(tmp_path)["regression"]
    assert (regression["sysmon_eid1_events"], regression["problems"]) == (2, [])
    _write(case / "id-m.json", "{} trailing")
    assert qc_sigma(tmp_path)["regression"]["problems"] == ["m: id-m.json is not valid bounded JSON"]


def test_sigma_qc_counts_conversion_failures(tmp_path, monkeypatch):
    from kestrix.core.errors import Reason, Rejected
    from kestrixbench import qc

    def fail(rule, mapping):
        raise Rejected(Reason.CONVERSION_FAILED, "backend refused")

    monkeypatch.setattr(qc, "to_lucene", fail)
    _write(
        tmp_path / SIGMA_RULES / "a.yml",
        RULE.format(title="A", rid="00000000-0000-4000-8000-00000000000a", value="\\\\a.exe"),
    )
    assert qc_sigma(tmp_path)["outcomes"] == {"unsupported:conversion_failed": 1}
