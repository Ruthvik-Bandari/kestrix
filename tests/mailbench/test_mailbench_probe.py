# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev-only feature runs and the aggregate probe, on tiny synthetic corpora."""

import json
from pathlib import Path

from mailbench_data import SENTINEL

from kestrixmailbench.build import build, read_meta
from kestrixmailbench.common import Layout
from kestrixmailbench.features import read_features, run_shard
from kestrixmailbench.probe import MIN_CELL, REPORT, cohorts_of, message_tags, run_probe
from kestrixmailbench.sources import Source
from kestrixmailbench.split import read_split, run_split

LIST_MAIL = (
    b"From: Ann <ann@sender.example>\nReply-To: list@lists.example.org\nList-Id: <dev.lists.example.org>\n"
    b"To: bob@example.org\nSubject: hello\nDate: Mon, 04 Mar 2002 10:00:00 +0000\nMessage-ID: <1@sender.example>\n\n"
    b"Please visit http://192.168.1.5/page or http://intranet/x. 100% free offer, act now.\n"
)


def build_chain(sources: tuple[Path, tuple[Source, ...]], root: Path, splits: tuple[str, ...]) -> Layout:
    raw, srcs = sources
    layout = Layout(root, 4)
    build(raw, layout, enron_sample=12, oversample=1.5, sources=srcs)
    run_split(layout, read_meta(layout))
    meta = {m["id"]: m for m in read_meta(layout)}
    for shard in range(4):
        run_shard(layout, shard, meta, read_split(layout), splits)
    return layout


def test_a_dev_only_run_never_analyzes_or_writes_the_test_split(
    sources: tuple[Path, tuple[Source, ...]], tmp_path: Path
) -> None:
    layout = build_chain(sources, tmp_path / "root", ("dev",))
    assert read_features(layout, "dev")
    assert not any(layout.feature_file(shard, "test").exists() for shard in range(4))


def test_message_tags_are_coarse_and_name_the_list_relation() -> None:
    tags = message_tags(LIST_MAIL)
    assert {"rt_foreign", "rt_eq:list-id", "rt_eq:any_list_header", "hdr:list-id", "ip:only_private"} <= tags
    assert {"host:single_label", "sp:free", "sp:act_now", "scheme:http"} <= tags
    assert not any("example.org" in tag or "192.168" in tag for tag in tags)


def test_cohorts_follow_the_content_verdict() -> None:
    row = {"label": "ham", "source": "spamassassin", "subset": "x/20021010_hard_ham/ham", "findings": []}
    assert cohorts_of(row) == ["ham_sa", "ham_sa_hard"]
    flagged = {**row, "findings": [["mail.sender.reply_to_mismatch", "medium", "sender"]]}
    assert cohorts_of(flagged) == ["ham_sa", "ham_sa_hard", "ham_sa_flagged", "ham_sa_reply_to_mismatch"]
    assert "phishing_no_finding" in cohorts_of(
        {"label": "phishing", "source": "nazario", "subset": "p", "findings": []}
    )


def test_probe_report_is_aggregate_only(sources: tuple[Path, tuple[Source, ...]], tmp_path: Path) -> None:
    base = build_chain(sources, tmp_path / "base", ("dev",))
    out = Layout(tmp_path / "round", 4)
    body = run_probe(out, base)
    text = (out.reports / REPORT).read_text()
    assert SENTINEL not in text and "sender.example" not in text
    assert json.loads(text) == body
    for cohort in body["cohorts"].values():
        assert all(count >= MIN_CELL for count in cohort["tags"].values())
    assert sum(c["n"] for name, c in body["cohorts"].items() if name in {"phishing", "spam", "ham_sa", "ham_enron"}) > 0
