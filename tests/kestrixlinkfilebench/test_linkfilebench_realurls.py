# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Common Crawl index sampling (a fake range fetcher) and the real-URL build, split, features and report."""

import gzip
import json
import os
from pathlib import Path

import pytest

import kestrixlinkfilebench.ccindex as cc
from kestrixlinkfilebench.__main__ import main
from kestrixlinkfilebench.common import LinkFileBenchError, kind_layout, write_private
from kestrixlinkfilebench.features import read_features
from kestrixlinkfilebench.report import dev_metrics, locked_test
from kestrixmailbench.metrics import Frame
from kestrixvul.evaluate import LockedEvalError


def cdx_line(surt: str, url: str, status: str = "200", mime: str = "text/html") -> str:
    record = {"url": url, "mime": mime, "mime-detected": mime, "status": status}
    return f"{surt} 20261009103758 {json.dumps(record)}"


def make_index(blocks: list[list[str]]) -> tuple[cc.ClusterIndex, dict[tuple[int, int], bytes]]:
    index = cc.ClusterIndex([], [], [], [])
    data: dict[tuple[int, int], bytes] = {}
    offset = 0
    for lines in blocks:
        raw = gzip.compress("\n".join(lines).encode())
        index.surts.append(lines[0].split(" ", 1)[0])
        index.files.append("cdx-00000.gz")
        index.offsets.append(offset)
        index.lengths.append(len(raw))
        data[(offset, len(raw))] = raw
        offset += len(raw)
    return index, data


def fetcher(data: dict[tuple[int, int], bytes]) -> cc.Fetch:
    return lambda _url, start, length: data[(start, length)]


def test_surt_ranges() -> None:
    assert cc.surt_prefix("bbc.co.uk") == "uk,co,bbc"
    lo, hi = cc.domain_range("example.com")
    inside = ["com,example)/a", "com,example,www)/b"]
    assert all(lo <= key < hi for key in inside) and not lo <= "com,example-shop)/" < hi
    lo, hi = cc.host_range("github.io")
    assert lo <= "io,github,alice)/" and lo > "io,github)/" and hi < "io,github-pages)/"


def test_domain_sample_takes_usable_html_only_and_stays_in_range() -> None:
    lines = [
        cdx_line("com,exam)/", "https://exam.com/"),
        cdx_line("com,example)/", "https://example.com/"),
        cdx_line("com,example)/a", "http://example.com/a?x=1"),
        cdx_line("com,example)/robots.txt", "https://example.com/robots.txt", mime="text/plain"),
        cdx_line("com,example)/gone", "https://example.com/gone", status="404"),
        cdx_line("com,example,blog)/p", "https://blog.example.com/p"),
        cdx_line("com,example-shop)/", "https://example-shop.com/"),
        cdx_line("ftp,example)/", "ftp://example.com/"),
    ]
    index, data = make_index([lines])
    urls, fetched = cc.sample_domain(fetcher(data), cc.CRAWL, index, "example.com", seed="s", per_domain=10, blocks=2)
    assert fetched == 1
    assert sorted(urls) == sorted(["https://example.com/", "http://example.com/a?x=1", "https://blog.example.com/p"])


def test_platform_sample_caps_urls_per_host_and_skips_the_apex() -> None:
    lines = [cdx_line("io,github)/", "https://github.io/")]
    lines += [cdx_line(f"io,github,alice)/p{i}", f"https://alice.github.io/p{i}") for i in range(5)]
    lines += [cdx_line("io,github,bob)/", "https://bob.github.io/")]
    lines += [cdx_line("io,github,www)/", "https://www.github.io/")]
    index, data = make_index([lines])
    urls, info = cc.sample_platform(fetcher(data), cc.CRAWL, index, "github.io", seed="s", blocks=5, per_host=2)
    hosts = sorted(cc.host_of(u) for u in urls)
    assert hosts == ["alice.github.io", "alice.github.io", "bob.github.io"]
    assert info["hosts"] == 2


def test_parse_helpers_ignore_malformed_lines() -> None:
    assert cc.parse_line("garbage") is None
    assert cc.parse_line("a b {not json") is None
    assert cc.usable_url({"url": "https://é.example/", "status": "200", "mime": "text/html"}) is None
    assert cc.usable_url({"url": "https://a.example/" + "x" * 3000, "status": "200", "mime": "text/html"}) is None
    index = cc.parse_cluster(["com,a)/ 2026\tcdx-00000.gz\t0\t10\t1", "short line"])
    assert len(index) == 1


def test_a_403_stops_the_run_instead_of_marking_domains_failed(tmp_path: Path) -> None:
    layout = kind_layout(tmp_path, "realurl", 2)
    base = layout.raw / "commoncrawl" / cc.CRAWL
    write_private(
        base / "cluster.idx", b"".join(f"com,d{i:04d})/ 2026\tcdx-00000.gz\t{i}\t5\t1\n".encode() for i in range(1500))
    )
    write_private(base / "terms-of-use.html", b"terms")
    write_private(layout.raw / "majestic" / "majestic_million.csv", b"GlobalRank,Domain\n1,d0001.com\n2,d0002.com\n")

    def blocked(_url: str, _start: int, _length: int) -> bytes:
        raise cc.BlockedError("HTTP 403")

    with pytest.raises(cc.BlockedError):
        cc.acquire_commoncrawl(layout, candidates=2, domains=2, fetch=blocked, workers=1)


def write_sample(tmp_path: Path) -> Path:
    rows = []
    for d in range(40):
        for k in range(4):
            scheme = "http" if k == 0 else "https"
            rows.append(
                {
                    "url": f"{scheme}://www.site{d}.example/a/{k}?q={k}",
                    "cohort": "top_domain",
                    "domain": f"site{d}.example",
                    "rank": d,
                }
            )
    for u in range(30):
        rows.append(
            {
                "url": f"https://user{u}.github.io/post/{u}",
                "cohort": "github.io",
                "domain": f"user{u}.github.io",
                "rank": None,
            }
        )
    rows.append(
        {"url": "https://user0.github.io/post/0", "cohort": "github.io", "domain": "user0.github.io", "rank": None}
    )
    rows.append({"url": "ftp://bad.example/", "cohort": "top_domain", "domain": "bad.example", "rank": 1})
    rows.append({"url": "https://carol.github.io/x", "cohort": "top_domain", "domain": "github.io", "rank": 5})
    path = tmp_path / "raw" / "commoncrawl" / cc.CRAWL / "urls.jsonl"
    write_private(path, b"".join((json.dumps(r) + "\n").encode() for r in rows))
    return tmp_path


def chain(root: Path, sha: str = "code-A") -> None:
    os.environ["KESTRIX_GIT_SHA"] = sha
    common = ["--root", str(root), "--kind", "realurl", "--shards", "2"]
    assert main(["build", *common]) == 0
    for shard in range(2):
        assert main(["features", *common, "--shard", str(shard), "--splits", "dev,test"]) == 0


def test_build_cohorts_groups_dedupe_and_report(tmp_path: Path) -> None:
    root = write_sample(tmp_path)
    try:
        chain(root)
        layout = kind_layout(root, "realurl", 2)
        build = json.loads((layout.reports / "build.json").read_text())
        assert build["kept"] == {
            "github.io": 31,
            "top_domain": 160,
        }  # carol.github.io is reclassified; duplicate dropped
        assert build["dropped"]["github.io|duplicate_exact"] == 1
        assert build["dropped"]["top_domain|invalid_url"] == 1
        manifest = json.loads(layout.split_manifest.read_text())
        assert sum(v["items"] for v in manifest["splits"].values()) == 191
        body = dev_metrics(layout, "realurl", reps=5)
        top = body["cohorts"]["top_domain"]
        assert (
            top["finding_items"]["not_https"] == top["finding_items"]["not_https"]
            and "not_https" in top["finding_items"]
        )
        assert (
            body["cohorts"]["github.io"]["finding_items"]["hosting_platform_subdomain"]
            == body["cohorts"]["github.io"]["n"]
        )
        assert "top_domain/http/path_or_query" in body["top_domain_by_shape"]
        text = (layout.reports / "realurl-dev-metrics.json").read_text()
        assert "site1.example" not in text and "user0" not in text
        assert all(r["split"] == "dev" for r in read_features(layout, "dev"))
        assert Frame(read_features(layout, "dev")).group_names
    finally:
        os.environ.pop("KESTRIX_GIT_SHA", None)


def test_locked_realurl_test_runs_once(tmp_path: Path) -> None:
    root = write_sample(tmp_path)
    try:
        chain(root)
        layout = kind_layout(root, "realurl", 2)
        out = locked_test(layout, "realurl", "t1", reps=5)
        assert json.loads(out.read_text())["systems"]["final"]["items"] > 0
        with pytest.raises(LockedEvalError):
            locked_test(layout, "realurl", "t2", reps=5)
    finally:
        os.environ.pop("KESTRIX_GIT_SHA", None)


def test_build_without_the_sample_names_the_missing_input(tmp_path: Path) -> None:
    layout = kind_layout(tmp_path, "realurl", 2)
    with pytest.raises(LinkFileBenchError, match="acquire-cc"):
        from kestrixlinkfilebench.realurls import build_realurls

        build_realurls(layout.raw, layout)


def test_platform_cap_keeps_whole_hosts_and_never_empties_a_platform(tmp_path: Path) -> None:
    from collections import Counter

    from kestrixlinkfilebench.realurls import _cap_platforms

    kept = [{"id": f"{h}-{i}", "source": "github.io", "group": f"h{h}"} for h in range(10) for i in range(3)]
    kept += [{"id": "t1", "source": cc.TOP_COHORT, "group": "d1"}]
    dropped: Counter[str] = Counter()
    out = _cap_platforms(kept, dropped, cap=7)
    hosts = {k["group"] for k in out if k["source"] == "github.io"}
    assert len([k for k in out if k["source"] == "github.io"]) == 6 and len(hosts) == 2  # whole hosts only
    assert dropped["github.io|platform_cap"] == 24 and any(k["id"] == "t1" for k in out)
    assert len(_cap_platforms(kept, Counter(), cap=1)) == 4  # the first host is always kept
