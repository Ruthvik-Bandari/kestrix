# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import httpx
import pytest

from kestrix.webcheck import checks
from kestrix.webcheck.models import Finding
from kestrix.webcheck.profile import profile_site
from kestrix.webcheck.scan import scan
from tests.webcheck.test_webcheck import ok_probe

HTML = {"content-type": ["text/html; charset=utf-8"]}
STATIC = b"<html><head><script src='/app.js'></script></head><body><h1>Portfolio</h1><a href='/x'>x</a></body></html>"
API = b"<html><script>fetch('/api/projects').then(r => r.json())</script></html>"
LOGIN = b"<form method='post' action='/login'><input name='u'><input type='password' name='p'></form>"


@pytest.mark.parametrize(
    ("headers", "body", "kind"),
    [
        (HTML, STATIC, "static"),
        (HTML, API, "static_api"),
        (HTML, LOGIN, "dynamic"),
        (
            HTML,
            b"<form><input name='name'><input type='email' name='email'><textarea name='m'></textarea></form>",
            "static_api",
        ),
        ({**HTML, "set-cookie": ["sid=1; Secure"]}, STATIC, "dynamic"),
        ({"content-type": ["application/json"]}, b'{"a": 1}', "static_api"),
    ],
)
def test_classification_from_page_evidence(headers, body, kind):
    profile = profile_site(headers, body, "https://site.test/")
    assert (profile.kind, profile.detected) == (kind, kind)
    assert profile.reasons


def test_evidence_counts_and_third_party_scripts():
    body = LOGIN + b"<script src='https://cdn.example.net/x.js'></script><script src='https://site.test/a.js'></script>"
    ev = profile_site(HTML, body, "https://www.site.test/").evidence
    assert (ev.forms, ev.post_forms, ev.password_fields, ev.input_fields) == (1, 1, 1, 2)
    assert ev.third_party_script_hosts == ["cdn.example.net"]  # same-site host is first-party


def test_declaration_can_raise_but_never_lower():
    raised = profile_site(HTML, STATIC, "https://site.test/", declared="dynamic")
    assert (raised.kind, raised.detected) == ("dynamic", "static")
    refused = profile_site(HTML, LOGIN, "https://site.test/", declared="static")
    assert refused.kind == "dynamic"
    assert any("You chose 'pages only', but this page has a password field" in r for r in refused.reasons)


def test_hostile_markup_is_counted_not_run():
    body = b"<scr<script>ipt>alert(1)</script><form><input type=password>" + b"<div>" * 50_000
    profile = profile_site(HTML, body, "https://site.test/")
    assert profile.kind == "dynamic"  # the password field still counts
    assert profile_site(HTML, b"\xff\xfe\x00garbage<<<>>>", "https://site.test/").kind == "static"


def _finding(fid, severity):
    return Finding(id=fid, severity=severity, title="", explanation="", recommendation="")


def test_static_lowers_context_findings_with_an_explanation():
    profile = profile_site(HTML, STATIC, "https://site.test/")
    found = {
        f.id: f
        for f in checks.apply_profile(
            [
                _finding("csp.missing", "medium"),
                _finding("framing.unprotected", "medium"),
                _finding("hsts.missing", "medium"),
            ],
            profile,
        )
    }
    assert (found["csp.missing"].severity, found["csp.missing"].baseline_severity) == ("low", "medium")
    assert found["framing.unprotected"].severity == "info"
    assert "a static site (" in found["framing.unprotected"].context
    assert found["hsts.missing"].severity == "medium" and found["hsts.missing"].baseline_severity is None


def test_third_party_scripts_keep_csp_severity_and_dynamic_is_unchanged():
    third = profile_site(HTML, b"<script src='https://cdn.example.net/x.js'></script>", "https://site.test/")
    assert checks.apply_profile([_finding("csp.missing", "medium")], third)[0].severity == "medium"
    dynamic = profile_site(HTML, LOGIN, "https://site.test/")
    assert checks.apply_profile([_finding("framing.unprotected", "medium")], dynamic)[0].severity == "medium"


def test_scan_of_a_static_portfolio_grades_in_context(fake_dns):
    headers = [
        ("content-type", "text/html"),
        ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
    ]
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(STATIC))

    report = scan("https://site.test/", transport=httpx.MockTransport(handler), probe=ok_probe)
    assert report.profile is not None and report.profile.kind == "static"
    by_id = {f.id: f for f in report.findings}
    assert by_id["csp.missing"].severity == "low" and by_id["framing.unprotected"].severity == "info"
    assert seen[-1].headers["accept-encoding"] == "identity"  # bounded read sees the real page size
    declared = scan("https://site.test/", transport=httpx.MockTransport(handler), probe=ok_probe, site_type="dynamic")
    assert declared.score < report.score  # the owner's "it has a login" restores full severity


def test_site_profile_is_the_most_sensitive_page_and_names_it():
    from kestrix.webcheck.profile import assess_page, combine_pages

    pages = [
        ("/", assess_page(HTML, STATIC, "https://site.test/", "The home page")),
        ("/contact", assess_page(HTML, b"<form><input name='m'></form>", "https://site.test/contact", "/contact")),
        ("/admin", assess_page(HTML, LOGIN, "https://site.test/admin", "/admin")),
        ("/staff", assess_page(HTML, LOGIN, "https://site.test/staff", "/staff")),
    ]
    site = combine_pages(pages)
    assert (site.kind, site.decided_by) == ("dynamic", "/admin")  # the first of equally sensitive pages
    assert site.reasons == ["/admin has a password field"]
    assert site.evidence.password_fields == 2 and site.evidence.forms == 3
    plain = combine_pages(pages[:1], declared="dynamic")
    assert plain.kind == "dynamic" and plain.decided_by is None
    assert plain.reasons[-1] == "You said this site has logins, so it was checked as a site with logins."
    lowered = combine_pages(pages[1:2], declared="static")
    assert lowered.kind == "static_api"
    assert lowered.reasons[-1] == (
        "You chose 'pages only', but /contact has a form with 1 input field(s) but no login or cookie, "
        "so it was checked as a site with a form."
    )
