# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The whole chain on tiny synthetic corpora: build, split, features, dev metrics and the once-only locked test."""

import json
from pathlib import Path

import pytest
from mailbench_data import SENTINEL

from kestrixmailbench.build import build, read_meta
from kestrixmailbench.common import Layout, MailBenchError, write_json
from kestrixmailbench.features import feature_errors, read_features, run_shard
from kestrixmailbench.metrics import CONTENT
from kestrixmailbench.report import dev_metrics, locked_test
from kestrixmailbench.sources import Source
from kestrixmailbench.split import read_split, run_split
from kestrixvul.evaluate import LockedEvalError, claim_locked

MODEL = {
    "schema_version": 1,
    "kind": "kestrix-mail-weights-candidate",
    "feature_set": CONTENT.to_json(),
    "intercept": -1.0,
    "weights": {"mail.intent.gambling_offer": 2.0, "mail.links.userinfo": 3.0},
    "interactions": [],
    "thresholds": {"suspicious": 0.5, "malicious": 2.5},
}


@pytest.fixture
def chain(sources: tuple[Path, tuple[Source, ...]], tmp_path: Path) -> Layout:
    raw, srcs = sources
    layout = Layout(tmp_path / "root", 4)
    build(raw, layout, enron_sample=12, oversample=1.5, sources=srcs)
    run_split(layout, read_meta(layout))
    meta = {m["id"]: m for m in read_meta(layout)}
    split_of = read_split(layout)
    for shard in range(4):
        run_shard(layout, shard, meta, split_of)
    return layout


def test_features_hold_no_text_and_cover_every_message(chain: Layout) -> None:
    dev = read_features(chain, "dev", None)
    for shard in range(4):
        assert SENTINEL not in chain.feature_file(shard, "dev").read_text()
        assert SENTINEL not in chain.feature_file(shard, "test").read_text()
        assert oct(chain.feature_file(shard, "dev").stat().st_mode & 0o777) == "0o600"
    assert feature_errors(chain) == {}
    assert {"id", "label", "source", "year", "verdict", "score", "findings", "counts"} <= set(dev[0])
    assert all(r["split"] == "dev" for r in dev)


def test_the_test_split_is_unreadable_without_a_claim(chain: Layout) -> None:
    with pytest.raises(MailBenchError, match="locked test split"):
        read_features(chain, "test")
    with pytest.raises(MailBenchError, match="locked test split"):
        read_features(chain, "test", claim=object())


def test_dev_metrics_report_is_aggregate_only(chain: Layout) -> None:
    body = dev_metrics(chain, reps=5)
    assert set(body["baseline"]) == {"all", "content", "content_strict"}
    text = (chain.reports / "mail-dev-metrics.json").read_text()
    for private in (SENTINEL, "user1", "user0", "nazario|"):
        assert private not in text
    assert body["leakage"]["era"]["cell_sizes"]["phishing_early"] >= 0
    assert body["split_manifest_sha256"]


def test_locked_test_runs_once_and_a_bad_preflight_does_not_burn_the_lock(chain: Layout, tmp_path: Path) -> None:
    bad = tmp_path / "mail-weights-bad.json"
    write_json(bad, {"kind": "something else"})
    with pytest.raises(MailBenchError, match="not a mail weights file"):
        locked_test(chain, [bad], "t1", reps=5)
    assert not (chain.reports / "LOCKED_EVAL.json").exists()

    good = tmp_path / "mail-weights-content.json"
    write_json(good, MODEL)
    out = locked_test(chain, [good], "t1", reps=5)
    report = json.loads(out.read_text())
    assert set(report["systems"]) >= {"baseline:all", "baseline:content", "learned:content"}
    assert report["weights_sha256"]["mail-weights-content.json"]
    claim = json.loads((chain.reports / "LOCKED_EVAL.json").read_text())
    assert claim["report"] == out.name and claim["report_sha256"] and claim["finished"]
    assert SENTINEL not in out.read_text()

    with pytest.raises(LockedEvalError, match="already ran"):
        locked_test(chain, [good], "t2", reps=5)


def test_claim_is_exclusive(tmp_path: Path) -> None:
    claim_locked(tmp_path, {"name": "a"})
    with pytest.raises(LockedEvalError):
        claim_locked(tmp_path, {"name": "b"})


def test_locked_test_needs_features_for_every_shard(chain: Layout, tmp_path: Path) -> None:
    chain.feature_file(2, "test").unlink()
    good = tmp_path / "mail-weights-content.json"
    write_json(good, MODEL)
    with pytest.raises(MailBenchError, match="run the features job"):
        locked_test(chain, [good], "t", reps=5)
    assert not (chain.reports / "LOCKED_EVAL.json").exists()


def test_cli_reports_missing_inputs_with_exit_status_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kestrixmailbench.__main__ import main

    assert main(["split", "--root", str(tmp_path)]) == 1
    assert "run build first" in capsys.readouterr().err
    assert main(["locked-test", "--root", str(tmp_path), "--weights", str(tmp_path / "mail-weights-x.json")]) == 1


def test_cli_runs_the_stages_in_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mailbench_data import make_sources

    import kestrixmailbench.build as build_module
    from kestrixmailbench.__main__ import main

    root = tmp_path / "root"
    monkeypatch.setattr(build_module, "SOURCES", make_sources(root / "raw"))
    common = ["--root", str(root), "--shards", "4"]
    assert main(["build", *common, "--enron-sample", "12"]) == 0
    for shard in range(4):
        assert main(["features", *common, "--shard", str(shard)]) == 0
    assert main(["dev-metrics", *common, "--bootstrap", "5"]) == 0
    assert (root / "reports" / "mail-dev-metrics.json").is_file()
    assert (root / "reports" / "split-manifest.json").is_file()
