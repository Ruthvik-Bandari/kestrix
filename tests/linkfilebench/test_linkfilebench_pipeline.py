# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The whole chain on tiny inputs: build, split, features, dev metrics and the once-only locked test."""

import json
import os
import shutil
from pathlib import Path

import pytest
from linkfilebench_data import SENTINEL_BYTES, SENTINEL_HOST, THREADS

from kestrixlinkfilebench.__main__ import main
from kestrixlinkfilebench.common import Layout, LinkFileBenchError, kind_layout
from kestrixlinkfilebench.features import code_versions, feature_errors, read_features
from kestrixlinkfilebench.report import dev_metrics, locked_test
from kestrixlinkfilebench.synth import FAMILIES
from kestrixvul.evaluate import LockedEvalError

SHARDS = {"link": 4, "file": 2}


def run_chain(root: Path, kind: str, splits: str = "dev,test", sha: str = "code-A") -> Layout:
    layout = kind_layout(root, kind, SHARDS[kind])
    common = ["--root", str(root), "--kind", kind, "--shards", str(SHARDS[kind])]
    os.environ["KESTRIX_GIT_SHA"] = sha
    if not layout.meta.is_file():
        assert main(["build", *common, *(["--majestic", "30"] if kind == "link" else [])]) == 0
    for shard in range(SHARDS[kind]):
        assert main(["features", *common, "--shard", str(shard), "--splits", splits]) == 0
    return layout


@pytest.fixture(autouse=True)
def _code_env() -> None:
    yield
    os.environ.pop("KESTRIX_GIT_SHA", None)


@pytest.fixture
def cli_inputs(inputs: Path) -> Path:
    return inputs


@pytest.mark.parametrize("kind", ["link", "file"])
def test_dev_metrics_report_is_aggregate_only(cli_inputs: Path, kind: str) -> None:
    layout = run_chain(cli_inputs, kind)
    body = dev_metrics(layout, kind, reps=5)
    text = (layout.reports / f"{kind}-dev-metrics.json").read_text()
    for private in (SENTINEL_HOST, SENTINEL_BYTES.decode(), "paypa1", "readme", "001.zip", "bad0host"):
        assert private not in text
    assert body["split_manifest_sha256"] and body["code"] == ["code-A"]
    assert body["feature_errors"] == {}
    if kind == "link":
        assert body["metrics"]["n"]["phishing"] > 0 and "matched" in body["leakage"]
        assert body["leakage"]["shape"]["benign_phiusiil"]["https"] == 1.0
    else:
        assert (
            body["synthetic"]["summary"]["malicious_families"] == sum(f.label == "malicious" for f in FAMILIES)
            and body["metrics"]["n"] > 0
        )
        assert body["synthetic"]["families"]["double_ext_exe"]["alarm_high"] == 20  # dev variants


def test_the_test_split_is_unreadable_without_a_claim(cli_inputs: Path) -> None:
    layout = run_chain(cli_inputs, "link")
    with pytest.raises(LinkFileBenchError, match="locked test split"):
        read_features(layout, "test")
    with pytest.raises(LinkFileBenchError, match="locked test split"):
        read_features(layout, "test", claim=object())


@pytest.mark.parametrize("kind", ["link", "file"])
def test_a_rules_round_never_analyzes_the_test_split(cli_inputs: Path, kind: str) -> None:
    layout = run_chain(cli_inputs, kind, splits="dev")
    assert not any(layout.feature_file(s, "test").exists() for s in range(SHARDS[kind]))
    assert code_versions(layout, "dev") == {"code-A"}
    with pytest.raises(LinkFileBenchError, match="no shard report for test"):
        code_versions(layout, "test")


def test_locked_test_runs_once_and_a_failed_preflight_does_not_burn_the_lock(cli_inputs: Path) -> None:
    layout = run_chain(cli_inputs, "link")
    layout.feature_file(2, "test").unlink()
    with pytest.raises(LinkFileBenchError, match="run the features job"):
        locked_test(layout, "link", "t1", reps=5)
    assert not (layout.reports / "LOCKED_EVAL.json").exists()
    run_chain(cli_inputs, "link")  # rewrites every feature file with the same code
    out = locked_test(layout, "link", "t1", reps=5)
    report = json.loads(out.read_text())
    assert set(report["systems"]) == {"final"} and report["split"] == "test" and report["code_by_system"]["final"]
    claim = json.loads((layout.reports / "LOCKED_EVAL.json").read_text())
    assert claim["report"] == out.name and claim["report_sha256"] and claim["finished"] and claim["kind"] == "link"
    assert SENTINEL_HOST not in out.read_text()
    with pytest.raises(LockedEvalError, match="already ran"):
        locked_test(layout, "link", "t2", reps=5)
    assert feature_errors(layout) == {}


def test_locked_test_refuses_dev_and_test_features_from_different_code(cli_inputs: Path) -> None:
    run_chain(cli_inputs, "file", splits="dev", sha="code-A")
    layout = run_chain(cli_inputs, "file", splits="test", sha="code-B")
    with pytest.raises(LinkFileBenchError, match="same synced code"):
        locked_test(layout, "file", "t", reps=5)
    assert not (layout.reports / "LOCKED_EVAL.json").exists()


def test_locked_test_can_evaluate_a_baseline_beside_the_final_rules(cli_inputs: Path, tmp_path: Path) -> None:
    layout = run_chain(cli_inputs, "file", sha="final-code")
    base_root = tmp_path / "base"
    base = kind_layout(base_root, "file", SHARDS["file"])
    base.reports.mkdir(parents=True)
    os.symlink(layout.work, base.root / "work")  # the baseline run reads the same private work directory
    shutil.copy(layout.split_manifest, base.split_manifest)
    common = ["--root", str(base_root), "--raw-root", str(cli_inputs), "--kind", "file", "--shards", "2"]
    os.environ["KESTRIX_GIT_SHA"] = "baseline-code"
    for shard in range(2):
        assert main(["features", *common, "--shard", str(shard)]) == 0
        assert main(["features", *common, "--shard", str(shard), "--splits", "test"]) == 0
    out = locked_test(layout, "file", "t", reps=5, baseline=base)
    report = json.loads(out.read_text())
    assert set(report["systems"]) == {"final", "baseline"}
    assert report["code_by_system"] == {"final": "final-code", "baseline": "baseline-code"}


def test_cli_reports_missing_inputs_and_a_missing_kind(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["split", "--root", str(tmp_path), "--kind", "link"]) == 1
    assert "run build first" in capsys.readouterr().err
    with pytest.raises(SystemExit, match="needs --kind"):
        main(["build", "--root", str(tmp_path)])
    assert main(["build", "--root", str(tmp_path), "--kind", "link"]) == 1
    assert "run acquire" in capsys.readouterr().err
    assert main(["features", "--root", str(tmp_path), "--kind", "link", "--shard", "0"]) == 1


def test_thread_list_matches_the_file_shard_default() -> None:
    from kestrixlinkfilebench.common import DEFAULT_SHARDS
    from kestrixlinkfilebench.files import thread_names

    assert len(thread_names()) == DEFAULT_SHARDS["file"] and len(set(thread_names())) == 20 and THREADS
