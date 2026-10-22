# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Link benchmark: label inversion, host-root URLs, deduplication, grouping, the split and the stored features."""

import zipfile
from pathlib import Path

import pytest
from linkfilebench_data import SENTINEL_HOST

from kestrixlinkfilebench.common import BENIGN, PHISHING, LinkFileBenchError, kind_layout, read_jsonl
from kestrixlinkfilebench.links import (
    build_links,
    exact_key,
    group_of,
    majestic_urls,
    near_key,
    read_meta,
    read_phiusiil,
    registered_domain,
    run_link_shard,
)
from kestrixlinkfilebench.split import check_disjoint, read_split, run_split


def test_phiusiil_label_one_is_legitimate_and_zero_is_phishing(tmp_path: Path) -> None:
    path = tmp_path / "p.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("d.csv", "URL,label\nhttps://good.example,1\nhttp://bad.example/login,0\n")
    assert list(read_phiusiil(path)) == [("https://good.example", BENIGN), ("http://bad.example/login", PHISHING)]


def test_phiusiil_refuses_an_unknown_label_or_a_missing_column(tmp_path: Path) -> None:
    path = tmp_path / "p.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("d.csv", "URL,label\nhttps://x.example,2\n")
    with pytest.raises(LinkFileBenchError, match="unexpected PhiUSIIL label"):
        list(read_phiusiil(path))
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("d.csv", "link,tag\nhttps://x.example,1\n")
    with pytest.raises(LinkFileBenchError, match="no URL and label columns"):
        list(read_phiusiil(path))


def test_majestic_hosts_become_host_root_urls_deterministically(inputs: Path) -> None:
    path = inputs / "raw" / "majestic" / "majestic_million.csv"
    urls = majestic_urls(path, 20)
    assert urls == majestic_urls(path, 20) and len(urls) == 20
    assert all(u.startswith("https://") and u.endswith("/") and u.count("/") == 3 for u in urls)
    assert {u.startswith("https://www.") for u in urls} == {True, False}


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.com.au", "example.com.au"),
        ("x.weebly.com", "weebly.com"),
        ("example.com", "example.com"),
        ("203.0.113.9", "203.0.113.9"),
        ("deep.sub.example.top", "example.top"),
    ],
)
def test_registered_domain_groups_conservatively(host: str, expected: str) -> None:
    assert registered_domain(host) == expected


def test_duplicate_keys() -> None:
    assert exact_key("HTTP://Dup.Example/a") == exact_key("http://dup.example/a")
    assert near_key("http://near.example/b") == near_key("https://www.near.example/b/?q=1")
    assert near_key("http://near.example/b") != near_key("http://near.example/c")


@pytest.fixture
def built(inputs: Path) -> tuple[Path, dict[str, object]]:
    layout = kind_layout(inputs, "link", 4)
    report = build_links(inputs / "raw", layout, majestic=30)
    return inputs, report


def test_build_drops_duplicates_conflicts_and_urls_without_a_host(built: tuple[Path, dict[str, object]]) -> None:
    root, report = built
    dropped = report["dropped"]
    assert isinstance(dropped, dict)
    assert dropped["phiusiil/phishing|duplicate_exact"] == 1
    assert dropped["phiusiil/phishing|duplicate_near"] == 1
    assert dropped["phiusiil/benign|conflicting_label"] == 1 and dropped["phiusiil/phishing|conflicting_label"] == 1
    assert dropped["phiusiil/phishing|unparsable"] == 1
    assert report["phiusiil_raw_label_counts"] == {"1_legitimate_to_benign": 41, "0_phishing": 47}
    meta = read_meta(kind_layout(root, "link", 4))
    kept = {m["source"] + "/" + m["label"] for m in meta}
    assert kept == {"phiusiil/benign", "phiusiil/phishing", "majestic/benign"}
    assert len({m["id"] for m in meta}) == len(meta)
    assert all(m["group"].startswith("d") and len(m["group"]) == 17 for m in meta)
    assert group_of("a.example.co.uk") == group_of("b.example.co.uk") != group_of("example.com")


def test_the_split_keeps_every_registered_domain_on_one_side(built: tuple[Path, dict[str, object]]) -> None:
    root, _ = built
    layout = kind_layout(root, "link", 4)
    meta = read_meta(layout)
    manifest = run_split(layout, meta, "link")
    split_of = read_split(layout)
    check_disjoint(meta, split_of)
    assert manifest["splits"]["dev"]["items"] + manifest["splits"]["test"]["items"] == len(meta)
    assert manifest["splits"]["test"]["items"] > 0
    assert "registered domain" in manifest["unit"]
    for source in ("phiusiil/benign", "phiusiil/phishing"):
        assert manifest["splits"]["dev"]["by_source_label"][source] > 0


def test_features_hold_no_url_and_split_files_are_private(built: tuple[Path, dict[str, object]]) -> None:
    root, _ = built
    layout = kind_layout(root, "link", 4)
    run_split(layout, read_meta(layout), "link")
    meta = {m["id"]: m for m in read_meta(layout)}
    split_of = read_split(layout)
    for shard in range(4):
        report = run_link_shard(layout, shard, meta, split_of, ("dev",))
        assert report["errors"] == {}
        assert not layout.feature_file(shard, "test").exists()  # a split left out is not analyzed or written
    rows = [r for shard in range(4) for r in read_jsonl(layout.feature_file(shard, "dev"))]
    assert rows and all("url" not in r and "host" not in r for r in rows)
    text = "".join(layout.feature_file(shard, "dev").read_text() for shard in range(4))
    assert SENTINEL_HOST not in text and "paypa1" not in text
    assert {"level", "score", "findings", "len", "path", "query", "https", "tld", "label", "source", "group"} <= set(
        rows[0]
    )
    for shard in range(4):
        assert oct(layout.feature_file(shard, "dev").stat().st_mode & 0o777) == "0o600"
    phishing = [r for r in rows if r["label"] == PHISHING]
    assert any(r["level"] in ("medium", "high") for r in phishing)
    assert all(r["level"] in ("none", "low") for r in rows if r["source"] == "majestic")
