# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Splitting mbox and tar inputs, dropping unreadable and duplicate messages, labelling and grouping."""

import base64
import io
import json
import stat
from pathlib import Path

from mailbench_data import SENTINEL, eml, mbox

from kestrixmailbench.build import build, group_key, near_key, read_meta
from kestrixmailbench.common import Layout, message_year, read_jsonl
from kestrixmailbench.ingest import enron_names, enron_select, enron_user, iter_enron, iter_tar_messages, split_mbox
from kestrixmailbench.sources import Source


def test_split_mbox_separates_messages_and_keeps_body_from_lines() -> None:
    first = eml(1, body="line one\n>From not a separator\nend")
    second = eml(2)
    parts = list(split_mbox(io.BytesIO(mbox([first, second]))))
    assert len(parts) == 2
    assert b">From not a separator" in parts[0]
    assert parts[1].startswith(b"From: Alice")


def test_split_mbox_ignores_empty_input() -> None:
    assert list(split_mbox(io.BytesIO(b""))) == []


def test_enron_selection_is_seeded_and_reads_only_the_selected(sources: tuple[Path, tuple[Source, ...]]) -> None:
    raw, _ = sources
    path = raw / "enron" / "enron.tar.gz"
    names = enron_names(path)
    assert len(names) == 30
    a, b = enron_select(names, 10, "seed"), enron_select(names, 10, "seed")
    assert a == b and len(a) == 10
    assert set(a) != set(enron_select(names, 10, "other-seed"))
    read = list(iter_enron(path, a))
    assert len(read) == 10
    assert {m.rank for m in read} == set(a.values())
    assert enron_user("maildir/user1/inbox/3.") == "user1"


def test_tar_messages_skip_cmds_and_report_origin(sources: tuple[Path, tuple[Source, ...]]) -> None:
    raw, _ = sources
    messages = list(iter_tar_messages(raw / "spamassassin" / "easy_ham.tar.bz2"))
    assert len(messages) == 10
    assert {m.origin for m in messages} == {"easy_ham"}
    assert len(list(iter_tar_messages(raw / "spamassassin" / "easy_ham.tar.bz2", limit=3))) == 3


def test_message_year_parses_dates_and_rejects_nonsense() -> None:
    assert message_year(eml(1, date="Mon, 04 Mar 2002 10:00:00 +0000")) == 2002
    assert message_year(eml(1, date="Mon, 04 Mar 1971 10:00:00 +0000")) is None
    assert message_year(b"Subject: x\n\nbody") is None
    assert message_year(eml(1, date="not a date")) is None


def test_near_key_ignores_digits_urls_and_reply_prefixes() -> None:
    a = near_key("Re: Offer 12", ("Visit http://a.example/x?id=1 now 100",))
    b = near_key("offer 99", ("visit http://b.example/y?id=7 now 250",))
    assert a == b
    assert near_key("offer", ("different words",)) != a
    assert near_key(None, ()) is None


def test_group_key_collapses_single_year_files() -> None:
    assert group_key("nazario", "phishing-2016", 2015, True) == "nazario|phishing-2016|-"
    assert group_key("nazario", "phishing1.mbox", 2005, False) == "nazario|phishing1.mbox|2005"
    assert group_key("enron", "alice", None, False) == "enron|alice|unk"


def test_build_filters_dedupes_labels_and_stays_private(
    sources: tuple[Path, tuple[Source, ...]], tmp_path: Path
) -> None:
    raw, srcs = sources
    layout = Layout(tmp_path / "root", 4)
    report = build(raw, layout, enron_sample=12, oversample=1.0, sources=srcs)
    # 9 messages in p2005 (one exact duplicate), 8 + 1 junk in p2006, 10 ham, 10 spam, 12 sampled Enron.
    assert report["dropped_by_reason"]["nazario"]["duplicate_exact"] == 1
    assert report["dropped_by_reason"]["nazario"]["invalid_input"] == 1
    assert report["kept"]["nazario/phishing"] == 16
    assert report["kept"]["spamassassin/ham"] == 10
    assert report["kept"]["spamassassin/spam"] == 10
    assert report["kept"]["enron/ham"] == 12
    assert report["kept"]["synthetic/ham"] > 0
    meta = read_meta(layout)
    ids = [m["id"] for m in meta]
    assert len(ids) == len(set(ids))
    by_id = {m["id"]: m for m in meta}
    assert {m["label"] for m in meta if m["source"] == "nazario"} == {"phishing"}
    one_year = {m["group"] for m in meta if m["origin"] == "p2005.mbox"}
    assert one_year == {"nazario|p2005.mbox|-"}
    assert {m["year"] for m in meta if m["origin"] == "p2006.mbox"} == {2006}
    assert all(m["subset"] == "maildir" for m in meta if m["source"] == "enron")
    # raw shards decode to the same hashes; files are private
    seen = 0
    for shard in range(4):
        path = layout.raw_shard(shard)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for item in read_jsonl(path):
            assert by_id[item["id"]]["shard"] == shard
            assert base64.b64decode(item["b64"])
            seen += 1
    assert seen == len(meta)
    assert stat.S_IMODE(layout.meta.stat().st_mode) == 0o600
    assert stat.S_IMODE(layout.work.stat().st_mode) == 0o700
    # the report carries no message text and no mailbox names
    text = (layout.reports / "build.json").read_text()
    assert SENTINEL not in text and "user1" not in text
    assert json.loads(text)["kept_total"] == len(meta)


def test_build_is_deterministic(sources: tuple[Path, tuple[Source, ...]], tmp_path: Path) -> None:
    raw, srcs = sources
    one, two = Layout(tmp_path / "a", 4), Layout(tmp_path / "b", 4)
    build(raw, one, enron_sample=12, oversample=1.5, sources=srcs)
    build(raw, two, enron_sample=12, oversample=1.5, sources=srcs)
    assert [m["id"] for m in read_meta(one)] == [m["id"] for m in read_meta(two)]


def test_enron_cap_keeps_the_requested_number(sources: tuple[Path, tuple[Source, ...]], tmp_path: Path) -> None:
    raw, srcs = sources
    layout = Layout(tmp_path / "r", 4)
    report = build(raw, layout, enron_sample=5, oversample=2.0, sources=srcs)
    assert report["kept"]["enron/ham"] == 5
    assert report["dropped_by_reason"]["enron"]["over_sample_cap"] == 5
