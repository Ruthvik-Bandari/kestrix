# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The dev/test split is deterministic, group-disjoint and stratified, and never evaluates anything."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from kestrixmailbench.common import Layout, MailBenchError
from kestrixmailbench.split import assign, check_disjoint, read_split, run_split


def meta_rows() -> list[dict[str, Any]]:
    rows = []
    n = 0
    for source, label, groups in (
        ("nazario", "phishing", [f"nazario|f{k}|-" for k in range(10)]),
        ("spamassassin", "spam", [f"spamassassin|s|{y}" for y in range(2002, 2008)]),
        ("enron", "ham", [f"enron|u{k}|2001" for k in range(8)]),
        ("spamassassin", "ham", ["spamassassin|only|2002"]),
    ):
        for group in groups:
            for _ in range(10):
                n += 1
                rows.append(
                    {"id": f"{n:064x}", "source": source, "label": label, "group": group, "year": 2002, "subset": "x"}
                )
    return rows


def test_assignment_is_deterministic_and_seeded() -> None:
    meta = meta_rows()
    assert assign(meta) == assign(meta)
    assert assign(meta, seed="other") != assign(meta)


def test_groups_never_straddle_and_each_stratum_reaches_test() -> None:
    meta = meta_rows()
    by_group = assign(meta)
    split_of = {m["id"]: by_group[m["group"]] for m in meta}
    check_disjoint(meta, split_of)
    test_by_stratum = Counter((m["source"], m["label"]) for m in meta if split_of[m["id"]] == "test")
    assert test_by_stratum[("nazario", "phishing")] > 0
    assert test_by_stratum[("spamassassin", "spam")] > 0
    assert test_by_stratum[("enron", "ham")] > 0


def test_test_share_stays_near_the_target() -> None:
    meta = meta_rows()
    by_group = assign(meta, test_fraction=0.3)
    sizes = Counter(m["group"] for m in meta)
    nazario = [g for g in by_group if g.startswith("nazario")]
    share = sum(sizes[g] for g in nazario if by_group[g] == "test") / sum(sizes[g] for g in nazario)
    assert 0.2 <= share <= 0.375


def test_a_single_group_stratum_stays_in_dev() -> None:
    assert assign(meta_rows())["spamassassin|only|2002"] == "dev"


def test_check_disjoint_catches_a_straddling_group() -> None:
    meta = meta_rows()[:2]
    with pytest.raises(MailBenchError, match="both"):
        check_disjoint(meta, {meta[0]["id"]: "dev", meta[1]["id"]: "test"})


def test_a_group_in_two_strata_is_an_error() -> None:
    meta = meta_rows()[:2]
    meta[1] = {**meta[1], "label": "ham"}
    with pytest.raises(MailBenchError, match="two strata"):
        assign(meta)


def test_run_split_writes_private_files_and_aggregate_manifest(tmp_path: Path) -> None:
    layout = Layout(tmp_path / "root", 4)
    meta = meta_rows()
    body = run_split(layout, meta)
    assert set(read_split(layout)) == {m["id"] for m in meta}
    assert oct(layout.split.stat().st_mode & 0o777) == "0o600"
    text = layout.split_manifest.read_text()
    assert "enron|u" not in text and "ids" not in json.loads(text)["splits"]["dev"]
    assert sum(v["messages"] for v in body["splits"].values()) == len(meta)
    assert body["splits"]["dev"]["ids_sha256"] != body["splits"]["test"]["ids_sha256"]


def test_read_split_requires_the_split(tmp_path: Path) -> None:
    with pytest.raises(MailBenchError, match="run split"):
        read_split(Layout(tmp_path))
