# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kestrix.core.errors import Reason, Rejected
from kestrix.core.netguard import check_url
from kestrix.webcheck import checks
from kestrix.webcheck.cli import app as cli_app
from kestrix.webcheck.grade import grade
from kestrix.webcheck.models import Finding, TlsInfo
from kestrix.webcheck.scan import scan

OK_TLS = TlsInfo(host="site.test", status="ok", protocol="TLSv1.3", days_remaining=90)
GOOD = {
    "strict-transport-security": ["max-age=31536000; includeSubDomains; preload"],
    "content-security-policy": ["default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"],
    "x-content-type-options": ["nosniff"],
    "referrer-policy": ["strict-origin-when-cross-origin"],
    "permissions-policy": ["camera=()"],
    "cross-origin-opener-policy": ["same-origin"],
    "set-cookie": ["sid=SECRETVALUE; Secure; HttpOnly; SameSite=Lax"],
}
DNS = {"site.test": ["93.184.216.34"], "evil.test": ["10.0.0.5"], "rebind.test": ["127.0.0.1"]}


def ids(findings):
    return {f.id for f in findings}


def test_hardened_site_has_no_findings_and_grades_a():
    findings = checks.evaluate(GOOD, "https", OK_TLS)
    assert findings == []
    assert grade(findings, "https", OK_TLS) == ("A", 100)


def test_missing_headers_are_reported():
    found = ids(checks.evaluate({}, "https", OK_TLS))
    assert {"hsts.missing", "csp.missing", "framing.unprotected", "xcto.missing", "referrer.weak"} <= found


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("script-src 'self' 'unsafe-inline'", "csp.unsafe_inline"),
        ("default-src 'self' 'unsafe-eval'", "csp.unsafe_eval"),
        ("script-src *", "csp.wildcard_source"),
        ("default-src https:", "csp.wildcard_source"),
    ],
)
def test_weak_csp(csp, expected):
    assert expected in ids(checks.check_csp({"content-security-policy": [csp]}))


STRONG_CSP = "default-src 'self'; object-src 'none'; base-uri 'none'"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        # Framing-only policy, as on the scanned portfolio: present but no XSS protection.
        (
            {"content-security-policy": ["frame-ancestors 'none'; upgrade-insecure-requests"]},
            {"csp.no_script_restriction"},
        ),
        ({"content-security-policy-report-only": [STRONG_CSP]}, {"csp.report_only"}),
        ({"content-security-policy": [STRONG_CSP]}, set()),
        ({"content-security-policy": ["script-src 'self'"]}, {"csp.object_src_open", "csp.base_uri_missing"}),
        # A nonce or hash makes browsers ignore 'unsafe-inline'; 'strict-dynamic' ignores host sources.
        (
            {
                "content-security-policy": [
                    f"{STRONG_CSP}; script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:"
                ]
            },
            set(),
        ),
        ({"content-security-policy": [f"{STRONG_CSP}; script-src 'sha256-xyz' 'unsafe-inline'"]}, set()),
        ({"content-security-policy": [f"{STRONG_CSP}; script-src 'self' 'unsafe-inline'"]}, {"csp.unsafe_inline"}),
        # Every enforced policy applies, so a strict second policy covers a weak first one.
        ({"content-security-policy": ["frame-ancestors 'none'", STRONG_CSP]}, set()),
        ({"content-security-policy": [f"script-src * , {STRONG_CSP}"]}, set()),
        (
            {"content-security-policy": ["script-src *", "script-src https:"]},
            {"csp.wildcard_source", "csp.object_src_open", "csp.base_uri_missing"},
        ),
    ],
)
def test_csp_strength(headers, expected):
    assert ids(checks.check_csp(headers)) == expected


def test_framing_reads_every_csp_policy():
    assert checks.check_framing({"content-security-policy": [STRONG_CSP, "frame-ancestors 'self'"]}) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=0", {"hsts.disabled"}),
        ("max-age=31536000; includeSubDomains", {"hsts.not_preload_ready"}),
        ("max-age=15552000; includeSubDomains; preload", {"hsts.not_preload_ready"}),
        ("max-age=63072000; includeSubDomains; preload", set()),
        ("max-age=31536000; preload", {"hsts.no_subdomains"}),
    ],
)
def test_hsts_details(value, expected):
    assert ids(checks.check_hsts({"strict-transport-security": [value]}, True)) == expected


@pytest.mark.parametrize(
    ("cookie", "violates"),
    [
        ("__Host-sid=v; Secure; Path=/; HttpOnly; SameSite=Lax", False),
        ("__Host-sid=v; Secure; Path=/; Domain=site.test; HttpOnly; SameSite=Lax", True),
        ("__Host-sid=v; Secure; Path=/app; HttpOnly; SameSite=Lax", True),
        ("__host-sid=v; Path=/; HttpOnly; SameSite=Lax", True),
        ("__Secure-sid=v; Secure; Domain=site.test; HttpOnly; SameSite=Lax", False),
        ("__Secure-sid=v; HttpOnly; SameSite=Lax", True),
    ],
)
def test_cookie_prefix_rules(cookie, violates):
    found = ids(checks.check_cookies({"set-cookie": [cookie]}, https=True))
    assert ("cookie.prefix_violation" in found) is violates


def test_hsts_edge_cases():
    assert ids(checks.check_hsts({"strict-transport-security": ["max-age=300"]}, True)) == {
        "hsts.short_max_age",
        "hsts.no_subdomains",
    }
    assert checks.check_hsts({}, https=False) == []


def test_cookie_checks_never_echo_values():
    findings = checks.check_cookies({"set-cookie": ["sid=SECRETVALUE", "pref=1; SameSite=None"]}, https=True)
    assert {"cookie.no_secure", "cookie.no_httponly", "cookie.no_samesite", "cookie.samesite_none_insecure"} <= ids(
        findings
    )
    assert all("SECRETVALUE" not in (f.evidence or "") for f in findings)


def test_disclosure_and_framing():
    found = ids(checks.check_disclosure({"server": ["nginx/1.18.0"], "x-powered-by": ["PHP/8.1"]}))
    assert found == {"disclosure.server_version", "disclosure.powered_by"}
    assert checks.check_disclosure({"server": ["cloudflare"]}) == []
    assert checks.check_framing({"x-frame-options": ["DENY"]}) == []


def test_grade_rubric_and_forced_f():
    lows = [Finding(id=f"x{i}", severity="low", title="", explanation="", recommendation="") for i in range(3)]
    assert grade(lows, "https", OK_TLS) == ("B", 88)
    assert grade([], "http", TlsInfo(host="h", status="not_https"))[0] == "F"
    assert grade([], "https", TlsInfo(host="h", status="expired"))[0] == "F"


def test_tls_findings():
    assert ids(checks.check_tls(TlsInfo(host="h", status="hostname_mismatch"))) == {"tls.hostname_mismatch"}
    assert ids(checks.check_tls(TlsInfo(host="h", status="ok", days_remaining=3))) == {"tls.expiring_soon"}


# ---------------------------------------------------------------- network layer (mocked)
def ok_probe(host, ip, port, timeout):
    return TlsInfo(host=host, status="ok", protocol="TLSv1.3", days_remaining=60)


def transport(routes):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        key = (request.headers["host"], request.url.path)
        status, headers = routes[key]
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(b"x" * 10))

    return httpx.MockTransport(handler), seen


def test_scan_follows_redirect_and_pins_ip(fake_dns):
    tx, seen = transport(
        {
            ("site.test", "/"): (301, {"location": "https://site.test/home"}),
            ("site.test", "/home"): (200, {k: v[0] for k, v in GOOD.items()}),
        }
    )
    report = scan("http://site.test/", transport=tx, probe=ok_probe)
    assert report.final_url == "https://site.test/home"
    assert [h.status_code for h in report.redirect_chain] == [301, 200]
    assert all(r.url.host == "93.184.216.34" for r in seen)  # connected to the validated IP
    assert seen[1].extensions["sni_hostname"] == "site.test"
    assert report.grade == "A"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.1.2.3/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://evil.test/",
        "http://rebind.test/",
    ],
)
def test_ssrf_targets_blocked(fake_dns, url):
    with pytest.raises(Rejected) as exc:
        scan(url, transport=transport({})[0], probe=ok_probe)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED


def test_redirect_into_private_network_blocked(fake_dns):
    tx, _ = transport({("site.test", "/"): (302, {"location": "http://evil.test/admin"})})
    with pytest.raises(Rejected) as exc:
        scan("http://site.test/", transport=tx, probe=ok_probe)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED


def test_redirect_loop_capped(fake_dns):
    tx, seen = transport({("site.test", "/"): (302, {"location": "/"})})
    with pytest.raises(Rejected, match="redirects"):
        scan("http://site.test/", transport=tx, probe=ok_probe)
    assert len(seen) == 6


def test_url_validation():
    for bad in ["ftp://site.test/", "http://user:pw@site.test/", "javascript:alert(1)", "http://"]:
        with pytest.raises(Rejected) as exc:
            check_url(bad)
        assert exc.value.reason is Reason.INVALID_URL


def test_private_targets_allowed_on_request(fake_dns):
    tx, _ = transport({("127.0.0.1:8080", "/"): (200, {})})
    report = scan("http://127.0.0.1:8080/", allow_private=True, transport=tx, probe=ok_probe)
    assert report.grade == "F"
    assert "https.not_used" in ids(report.findings)


def test_api_and_cli(monkeypatch):
    from kestrix.webcheck import api, cli

    monkeypatch.setattr(api, "scan", lambda url, allow_private, site_type: _fake_report())
    monkeypatch.setattr(cli, "scan", lambda url, allow_private, site_type: _fake_report())
    app = FastAPI()
    app.include_router(api.router)
    body = TestClient(app).post("/api/webcheck", json={"url": "https://site.test"}).json()
    assert body["grade"] == "A"
    assert "authorized" in body["notice"]
    result = CliRunner().invoke(cli_app, ["scan", "https://site.test"])
    assert result.exit_code == 0 and "grade A" in result.output


def _fake_report():
    from kestrix.webcheck.models import Report, Timings

    return Report(
        requested_url="https://site.test",
        final_url="https://site.test",
        status_code=200,
        headers_checked=True,
        redirect_chain=[],
        tls=OK_TLS,
        grade="A",
        score=100,
        findings=[],
        timings=Timings(total_ms=1, http_ms=1, tls_ms=0),
    )


def test_cli_rejected_exit_code(monkeypatch):
    from kestrix.webcheck import cli

    def boom(url, allow_private, site_type):
        raise Rejected(Reason.TARGET_NOT_ALLOWED, "private")

    monkeypatch.setattr(cli, "scan", boom)
    assert CliRunner().invoke(cli_app, ["scan", "http://10.0.0.1"]).exit_code == 2


# ---------------------------------------------------------------- conformance pages (full scan, mocked network)
# Each page sets one known-bad header set; the scan must report exactly the expected findings.
CONFORMANCE = {
    "csp-framing-only": (
        {**GOOD, "content-security-policy": ["frame-ancestors 'none'"]},
        {"csp.no_script_restriction"},
    ),
    "csp-report-only": (
        {k: v for k, v in GOOD.items() if k != "content-security-policy"}
        | {"content-security-policy-report-only": GOOD["content-security-policy"], "x-frame-options": ["DENY"]},
        {"csp.report_only"},
    ),
    "hsts-disabled": ({**GOOD, "strict-transport-security": ["max-age=0"]}, {"hsts.disabled"}),
    "cookie-flags": (
        {**GOOD, "set-cookie": ["sid=v", "__Host-t=v; Secure; Path=/; Domain=site.test; HttpOnly; SameSite=Lax"]},
        {"cookie.no_secure", "cookie.no_httponly", "cookie.no_samesite", "cookie.prefix_violation"},
    ),
    "disclosure": ({**GOOD, "x-powered-by": ["Next.js"]}, {"disclosure.powered_by"}),
}


@pytest.mark.parametrize("page", sorted(CONFORMANCE))
def test_conformance_pages(fake_dns, page):
    headers, expected = CONFORMANCE[page]
    tx, _ = transport({("site.test", "/"): (200, [(k, v) for k, vals in headers.items() for v in vals])})
    report = scan("https://site.test/", transport=tx, probe=ok_probe)
    assert ids(report.findings) == expected
