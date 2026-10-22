# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Announced software versions: banner parsing, the bundled data, and the findings (synthetic headers only)."""

from __future__ import annotations

import json
from datetime import date, timedelta

import httpx
import pytest

from kestrix.webcheck import exposure
from kestrix.webcheck.checks import merge_findings
from kestrix.webcheck.exposure import check_exposure, read_banners, staleness_note
from kestrix.webcheck.scan import scan
from tests.webcheck.test_webcheck import GOOD, ids, ok_probe, transport

TODAY = date(2026, 10, 22)


def found(headers: dict[str, list[str]], body: bytes = b"", today: date = TODAY):
    return {f.id: f for f in check_exposure(headers, body, today)}


def test_the_bundled_data_is_valid_and_every_entry_names_a_source():
    data = exposure.load_data()
    assert data.generated <= date.today()
    assert {"php", "nginx", "apache", "iis", "openssl", "node", "drupal"} <= set(data.products)
    for product in data.products.values():
        assert product.source.startswith("https://")
        assert all((e.source or product.source).startswith("https://") for e in product.branches)
    php = {e.branch: e.eol for e in data.products["php"].branches}
    assert php["7.4"] == "2022-11-28" and php["5.6"] == "2018-12-31" and php["8.1"] == "2025-12-31"
    for adv in data.advisories:
        assert adv.source.startswith("https://") and adv.cves and adv.fixed


def test_banners_are_read_from_headers_and_meta_generator():
    headers = {
        "server": ["Apache/2.4.41 (Ubuntu) PHP/7.4.3 OpenSSL/1.1.1f"],
        "x-powered-by": ["PHP/7.4.3", "Express"],
        "via": ["1.1 varnish, 1.1 nginx/1.18.0"],
        "x-aspnet-version": ["4.0.30319"],
        "x-generator": ["Drupal 10 (https://www.drupal.org)"],
        "content-type": ["text/html"],
    }
    html = b'<html><head><META NAME="Generator" CONTENT="WordPress 6.4.2"></head></html>'
    seen = {(b.product, b.version): b.sources for b in read_banners(headers, html)}
    assert seen[("apache", "2.4.41")] == ("Server",)
    assert seen[("php", "7.4.3")] == ("Server", "X-Powered-By")
    assert seen[("openssl", "1.1.1f")] == ("Server",)
    assert seen[("nginx", "1.18.0")] == ("Via",)
    assert seen[("aspnet", "4.0.30319")] == ("X-AspNet-Version",)
    assert seen[("drupal", "10")] == ("X-Generator",)
    assert seen[("wordpress", "6.4.2")] == ('meta name="generator"',)
    assert not any(b.product == "express" for b in read_banners(headers))


def test_hostile_input_is_bounded_and_ignored():
    junk = {"server": ["x" * 5000 + "/1.2.3", "nginx/" + "9" * 5000], "x-powered-by": ["PHP/" + "1." * 2000]}
    assert len(read_banners(junk)) <= 20
    body = b"<meta name=generator content='WordPress 5.0'>" + b"<" * 100_000
    assert read_banners({"content-type": ["text/html"]}, body)[0].version == "5.0"
    assert read_banners({"content-type": ["application/json"]}, body) == []  # not HTML: not parsed


@pytest.mark.parametrize(
    ("headers", "severity", "branch"),
    [
        ({"x-powered-by": ["PHP/7.4.33"]}, "high", "PHP 7.4"),  # EOL for years, and the advisory leaves it unfixed
        ({"server": ["Microsoft-IIS/8.5"]}, "high", "Microsoft IIS 8.5"),  # EOL 2023-10-10, over a year
        ({"server": ["Apache/2.2.34 (Unix)"]}, "high", "Apache httpd 2.2"),
        ({"server": ["Apache/1.3.37"]}, "high", "Apache httpd 1.3"),  # undated, vendor says do not use
        ({"x-powered-by": ["PHP/8.1.20"]}, "high", "PHP 8.1"),
        ({"server": ["Apache/2.4.58 OpenSSL/3.0.13"]}, "medium", "OpenSSL 3.0"),  # undated, no severity override
    ],
)
def test_eol_branches_are_flagged_with_the_branch_and_source(headers, severity, branch):
    finding = found(headers)["exposure.eol_version"]
    assert finding.severity == severity
    assert branch in finding.title and finding.cwe == ["CWE-1104"]
    assert "https://" in (finding.evidence or "") and "stop announcing" in finding.recommendation


def test_php_74_message_cites_the_date_and_the_open_advisory():
    f = found({"x-powered-by": ["PHP/7.4.33"]})["exposure.eol_version"]
    assert "end of life since 2022-11-28" in f.explanation
    assert "CVE-2026-109618" in f.explanation and "CVE-2026-109619" in f.explanation
    assert "no longer receive updates from the PHP project" in f.explanation
    assert "expose_php = Off" in f.recommendation
    assert "can be wrong" in f.explanation and "not thereby up to date" in f.explanation
    assert "end of life 2022-11-28; https://www.php.net/eol.php" in (f.evidence or "")


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("8.2.34", True),
        ("8.2.35", False),
        ("8.3.35", True),
        ("8.3.36", False),
        ("8.4.26", True),
        ("8.4.27", False),
        ("8.5.11", True),
        ("8.5.12", False),
        ("8.5.13", False),
        ("8.6.0", False),  # a branch with no stated range is not guessed at
    ],
)
def test_the_php_advisory_matches_only_stated_ranges(version, affected):
    f = found({"x-powered-by": [f"PHP/{version}"]})
    assert ("exposure.known_vulnerable_version" in f) is affected
    if affected:
        vulnerable = f["exposure.known_vulnerable_version"]
        assert vulnerable.severity == "high" and vulnerable.cwe == ["CWE-937"]
        assert "CVE-2026-109618" in (vulnerable.evidence or "") and "php.net/archive/2026.php" in (
            vulnerable.evidence or ""
        )


def test_a_distribution_build_gets_a_backport_caveat():
    f = found({"server": ["Apache/2.4.41 (Ubuntu) PHP/8.2.20-1ubuntu1"]})
    assert "backported fixes" in f["exposure.known_vulnerable_version"].explanation


def test_a_supported_branch_becomes_end_of_life_after_its_date():
    headers = {"x-powered-by": ["PHP/8.2.40"]}
    assert "exposure.eol_version" not in found(headers, today=date(2026, 12, 31))
    after = found(headers, today=date(2027, 1, 1))["exposure.eol_version"]
    assert after.severity == "medium" and "2026-12-31" in after.explanation
    assert found({"x-powered-by": ["PHP/8.5.12"]}) == {}


def test_nginx_legacy_branches_are_low_and_current_ones_are_silent():
    f = found({"server": ["nginx/1.18.0"]})
    assert set(f) == {"exposure.outdated_branch"} and f["exposure.outdated_branch"].severity == "low"
    assert "nginx.org" in f["exposure.outdated_branch"].explanation
    assert found({"server": ["nginx/1.30.6"]}) == {}
    assert found({"server": ["nginx/1.27.0"]}) == {}  # not in the data: no claim


def test_node_and_drupal_use_their_published_schedules():
    assert found({"x-powered-by": ["Node.js/12.22.0"]})["exposure.eol_version"].severity == "high"
    assert found({"x-powered-by": ["Node.js/26.0.0"]}) == {}
    f = found({"x-generator": ["Drupal 7 (https://www.drupal.org)"]})
    assert set(f) == {"exposure.eol_version", "disclosure.generator_version"}


def test_cms_and_framework_versions_are_announced_as_low_disclosure():
    f = found(
        {"x-aspnet-version": ["4.0.30319"], "content-type": ["text/html"]},
        b'<meta name="generator" content="WordPress 6.4.2">',
    )
    assert set(f) == {"disclosure.generator_version"}
    assert f["disclosure.generator_version"].severity == "low" and f["disclosure.generator_version"].cwe == ["CWE-200"]
    assert "WordPress 6.4.2" in (f["disclosure.generator_version"].evidence or "")


def test_no_version_banner_means_no_finding():
    assert found({"server": ["cloudflare"], "x-powered-by": ["Express"]}) == {}
    assert found({}) == {}


def test_several_end_of_life_components_make_one_finding():
    f = check_exposure({"server": ["Apache/2.2.34 PHP/5.6.40 OpenSSL/1.0.2k"]}, b"", TODAY)
    assert [x.id for x in f] == ["exposure.eol_version"]
    assert "3 components" in f[0].title and f[0].evidence and f[0].evidence.count("\n") == 2


def test_staleness_note_appears_only_for_old_data():
    generated = exposure.load_data().generated
    assert staleness_note(generated + timedelta(days=30)) is None
    note = staleness_note(generated + timedelta(days=31))
    assert note and "31 days old" in note and "refresh_exposure_data.py" in note


def test_a_scan_reports_the_finding_and_the_stale_data_note(fake_dns, monkeypatch):
    headers = {**GOOD, "x-powered-by": ["PHP/7.4.33"], "server": ["nginx/1.18.0"]}
    tx, seen = transport({("site.test", "/"): (200, [(k, v) for k, vals in headers.items() for v in vals])})
    fresh = scan("https://site.test/", transport=tx, probe=ok_probe, scope="page")
    assert {"exposure.eol_version", "exposure.outdated_branch", "disclosure.server_version"} <= ids(fresh.findings)
    assert fresh.notes == [] or "days old" in fresh.notes[0]
    monkeypatch.setattr(exposure, "_today", lambda: date(2027, 6, 1))
    stale = scan("https://site.test/", transport=tx, probe=ok_probe, scope="page")
    assert len(stale.notes) == 1 and "days old" in stale.notes[0]
    assert len(seen) == 2  # still one GET per scan: nothing extra is sent


def test_whole_site_scans_merge_the_finding_across_pages():
    old = check_exposure({"x-powered-by": ["PHP/7.4.33"]}, b"", TODAY)
    older = check_exposure({"x-powered-by": ["PHP/5.6.40"]}, b"", TODAY)
    merged = {f.id: f for f in merge_findings([("/", old), ("/blog", older)])}
    assert merged["exposure.eol_version"].pages == ["/", "/blog"]


def test_a_whole_site_scan_reads_the_generator_tag_from_a_page_body(fake_dns):
    def handler(request: httpx.Request) -> httpx.Response:
        body = b'<html><head><meta name="generator" content="Drupal 7 (https://www.drupal.org)"></head><body>hi</body></html>'
        return httpx.Response(
            200 if request.url.path == "/" else 404,
            headers=[*[(k, v) for k, vals in GOOD.items() for v in vals], ("content-type", "text/html")],
            stream=httpx.ByteStream(body),
        )

    report = scan("https://site.test/", transport=httpx.MockTransport(handler), probe=ok_probe, scope="site")
    drupal = next(f for f in report.findings if f.id == "exposure.eol_version")
    assert "Drupal 7" in drupal.title and drupal.pages == ["/"]


def test_the_data_file_is_plain_json():
    path = exposure.resources.files("kestrix.webcheck") / "data" / "exposure.json"
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
