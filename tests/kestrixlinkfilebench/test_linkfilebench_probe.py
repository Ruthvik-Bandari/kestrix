# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The rule-round probes: tags describe URL and file shapes; the report never holds a URL, host or name."""

import json
from pathlib import Path

import pytest
from linkfilebench_data import SENTINEL_BYTES, SENTINEL_HOST, THREADS

from kestrixlinkfilebench.__main__ import main
from kestrixlinkfilebench.probe import MIN_CELL, link_tags, platform_family


def test_platform_family_needs_a_user_subdomain() -> None:
    assert platform_family("someone.weebly.com") == "site_builder"
    assert platform_family("x.y.github.io") == "static_or_cloud_hosting"
    assert platform_family("weebly.com") is None and platform_family("www.weebly.com") is None
    assert platform_family("example.com") is None


def test_link_tags_describe_the_shape_only() -> None:
    tags = link_tags("http://a1b2c3-login-secure.top/wp-content/x.php?next=http://other")
    assert {"label_hyphens_ge2", "label_digits_ge3", "path_has_ext_php_html_asp", "query_has_url"} <= tags
    assert link_tags("https://example.com/") == set()
    assert "platform:dynamic_dns_or_tunnel" in link_tags("https://host.duckdns.org/")


@pytest.mark.parametrize("kind", ["link", "file"])
def test_probe_report_holds_counts_for_dev_items_only(inputs: Path, kind: str) -> None:
    shards = {"link": "4", "file": "2"}[kind]
    common = ["--root", str(inputs), "--kind", kind, "--shards", shards]
    assert main(["build", *common, *(["--majestic", "30"] if kind == "link" else [])]) == 0
    for shard in range(int(shards)):
        assert main(["features", *common, "--shard", str(shard), "--splits", "dev"]) == 0
    assert main(["probe", *common]) == 0
    out = inputs / kind / "reports" / f"{kind}-probe.json"
    text = out.read_text()
    body = json.loads(text)
    assert body["split"] == "dev" and body["min_cell"] == MIN_CELL
    for private in (SENTINEL_HOST, SENTINEL_BYTES.decode(), "paypa1", "001.zip", "readme"):
        assert private not in text
    cohorts = body["cohorts"]
    assert all(c["n"] > 0 for c in cohorts.values())
    assert all(v >= MIN_CELL for c in cohorts.values() for v in c["tags"].values())
    assert ("phishing" in cohorts) if kind == "link" else ("govdocs_all" in cohorts)
    assert THREADS
