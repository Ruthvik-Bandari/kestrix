# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Whole-site scanning against local lab servers (127.0.0.1, ``allow_private``) and a mocked network.

Lab pages are synthetic. ``Lab.log`` records every request the scanner sent, so each safety claim is
checked against what actually arrived at the server.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kestrix.webcheck import api, cli, crawl
from kestrix.webcheck.fetch import USER_AGENT
from kestrix.webcheck.models import EXTRA_REQUEST_CAP, NOTICE_PAGE, NOTICE_SITE, PAGE_CAP, Report
from kestrix.webcheck.scan import scan
from tests.webcheck.conftest import DNS
from tests.webcheck.test_webcheck import GOOD, OK_TLS, _fake_report, ok_probe

HTML = [("Content-Type", "text/html; charset=utf-8")]
Route = tuple[int, list[tuple[str, str]], bytes] | Callable[[], tuple[int, list[tuple[str, str]], bytes]]


def page(body: str, *headers: tuple[str, str]) -> tuple[int, list[tuple[str, str]], bytes]:
    return 200, [*HTML, *headers], f"<html><body>{body}</body></html>".encode()


class Lab:
    """A threaded HTTP server on 127.0.0.1 with fixed routes; unknown paths are 404."""

    def __init__(self, routes: dict[str, Route]) -> None:
        self.routes = routes
        self.log: list[dict[str, object]] = []
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def serve(self) -> None:
                lab.log.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                route = lab.routes.get(self.path, (404, HTML, b"<html>not found</html>"))
                status, headers, body = route() if callable(route) else route
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = serve

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def paths(self) -> list[str]:
        return [str(entry["path"]) for entry in self.log]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def make_lab(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[dict[str, Route]], Lab]]:
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)
    labs: list[Lab] = []

    def make(routes: dict[str, Route]) -> Lab:
        labs.append(Lab(routes))
        return labs[-1]

    yield make
    for lab in labs:
        lab.close()


def run(lab: Lab, **kwargs: object) -> Report:
    return scan(lab.url + "/", allow_private=True, probe=ok_probe, **kwargs)  # type: ignore[arg-type]


def by_path(report: Report) -> dict[str, object]:
    return {p.path: p for p in report.pages}


def test_site_scan_finds_linked_sitemap_and_unlinked_login_pages(make_lab):
    other = make_lab({"/": page("other site")})
    lab = make_lab({})
    lab.routes.update(
        {
            "/": page(
                "<a href='/about'>a</a><a href='/about#team'>again</a><a href='#top'>t</a>"
                f"<a href='{other.url}/x'>off</a><a href='/logo.png'>i</a><a href='mailto:a@b.example'>m</a>"
                "<a href='/files/report.pdf'>p</a><a href='javascript:void(0)'>j</a><a href='/data'>d</a>"
                "<a href='/boom'>b</a><a href='/gone'>g</a>"
            ),
            "/about": page("<h1>About</h1>"),
            "/sitemap.xml": (
                200,
                [("Content-Type", "application/xml")],
                f"<urlset><url><loc>{lab.url}/blog</loc></url><url><loc>{lab.url}/about</loc></url></urlset>".encode(),
            ),
            "/blog": page("posts"),
            "/admin/login": page("<form method='post'><input name='u'><input type='password' name='p'></form>"),
            "/data": (200, [("Content-Type", "application/json")], b"{}"),
            "/boom": (500, HTML, b"oops"),
        }
    )
    report = run(lab)
    assert report.scope == "site" and report.notice == NOTICE_SITE
    pages = by_path(report)
    assert {p: (v.found_via, v.outcome, v.status_code) for p, v in pages.items()} == {
        "/": ("start", "checked", 200),
        "/about": ("link", "checked", 200),
        "/data": ("link", "not_html", 200),
        "/boom": ("link", "http_error", 500),
        "/gone": ("link", "http_error", 404),
        "/blog": ("sitemap", "checked", 200),
        "/login": ("probe", "http_error", 404),
        "/signin": ("probe", "http_error", 404),
        "/admin": ("probe", "http_error", 404),
        "/admin/login": ("probe", "checked", 200),
        "/account": ("probe", "http_error", 404),
        "/wp-login.php": ("probe", "http_error", 404),
    }
    assert list(pages) == [
        "/", "/about", "/data", "/boom", "/gone", "/blog", "/login", "/signin", "/admin", "/admin/login", "/account", "/wp-login.php"
    ]  # fmt: skip
    # Not fetched: the other site, the image, mailto:, the PDF and javascript:; the fragment and duplicate cost nothing.
    assert report.links_skipped == 5 and report.sitemap_entries == 2
    assert not {"/logo.png", "/files/report.pdf", "/x"} & set(lab.paths()) and other.log == []
    assert report.requests_sent == len(lab.log) == 13  # 12 pages + the sitemap
    assert report.limits_reached == []
    # The unlinked login page makes the site dynamic, and the reason names it.
    assert report.profile is not None
    assert (report.profile.kind, report.profile.decided_by) == ("dynamic", "/admin/login")
    assert report.profile.reasons[0] == "/admin/login has a password field"
    assert pages["/admin/login"].kind == "dynamic" and pages["/about"].kind == "static"


def test_the_start_page_alone_is_judged_when_scope_is_page(make_lab):
    lab = make_lab({"/": page("<a href='/admin/login'>staff</a>"), "/admin/login": page("<input type=password>")})
    report = run(lab, scope="page")
    assert lab.paths() == ["/"] and report.requests_sent == 1
    assert (report.scope, report.pages, report.notice) == ("page", [], NOTICE_PAGE)
    assert report.profile is not None and report.profile.kind == "static"
    # A cheap clue, not a new kind: the page points at a login it did not check.
    assert any("links to /admin/login" in r and "other pages" in r for r in report.profile.reasons)
    assert report.profile.reasons[0] == "This page has no forms, cookies or API calls"


def test_a_redirect_that_leaves_the_site_is_not_followed(make_lab):
    elsewhere = make_lab({"/landing": page("elsewhere")})
    lab = make_lab({"/": page("<a href='/go'>go</a>")})
    lab.routes["/go"] = (302, [("Location", f"{elsewhere.url}/landing")], b"")
    result = by_path(run(lab))["/go"]
    assert (result.outcome, result.status_code) == ("redirects_off_site", 302)
    assert "127.0.0.1" in str(result.detail) and "not followed" in str(result.detail)
    assert elsewhere.log == []


def test_a_redirect_to_a_page_already_checked_is_not_judged_twice(make_lab):
    lab = make_lab({"/": page("hi"), "/admin/login": page("<input type=password>")})
    lab.routes["/login"] = (302, [("Location", "/admin/login")], b"")
    pages = by_path(run(lab))
    assert pages["/login"].outcome == "checked" and pages["/login"].detail == "redirected to /admin/login"
    assert pages["/admin/login"].outcome == "duplicate"


def test_a_hostile_sitemap_is_bounded(make_lab):
    locs = "".join(f"<loc>/p{i}</loc>" for i in range(100_000))
    bomb = (
        "<!DOCTYPE x [<!ENTITY a 'aaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;'>]><urlset>"
        + "<loc>&b;&b;</loc>" * 50
    )
    lab = make_lab({"/": page("hi")})
    lab.routes["/sitemap.xml"] = (
        200,
        [("Content-Type", "text/xml")],
        (bomb + "<loc>" * 1000 + locs).encode()[:2_000_000],
    )
    started = time.monotonic()
    report = run(lab)
    assert time.monotonic() - started < 10
    assert report.sitemap_entries <= crawl.MAX_SITEMAP_ENTRIES
    assert report.limits_reached == ["page_cap"] and len(report.pages) <= PAGE_CAP
    assert len(lab.log) <= PAGE_CAP + 1
    assert all("aaaaaaaaaa" not in p.path for p in report.pages)  # entities are never expanded


def test_a_nested_sitemap_index_is_not_followed(make_lab):
    lab = make_lab(
        {
            "/": page("hi"),
            "/sitemap.xml": (
                200,
                HTML,
                b"<sitemapindex><sitemap><loc>/sitemap-posts.xml</loc></sitemap></sitemapindex>",
            ),
        }
    )
    report = run(lab)
    assert "/sitemap-posts.xml" not in lab.paths() and report.links_skipped == 1


def test_the_page_cap_holds_and_login_probes_keep_their_slots(make_lab):
    lab = make_lab({"/": page("".join(f"<a href='/n{i}'>{i}</a>" for i in range(70)))})
    report = run(lab)
    assert len(report.pages) == PAGE_CAP and report.limits_reached == ["page_cap"]
    assert len(lab.log) == report.requests_sent == PAGE_CAP + 1  # 50 pages and the sitemap
    assert {"/login", "/signin", "/admin", "/admin/login", "/account", "/wp-login.php"} <= set(by_path(report))
    assert [p.path for p in report.pages][1:44] == [f"/n{i}" for i in range(43)]


def test_redirects_and_the_sitemap_share_a_small_extra_budget(make_lab):
    lab = make_lab({"/": page("".join(f"<a href='/r{i}'>{i}</a>" for i in range(30)))})
    for i in range(30):
        lab.routes[f"/r{i}"] = (302, [("Location", f"/t{i}")], b"")
        lab.routes[f"/t{i}"] = page(f"t{i}")
    report = run(lab)
    assert "request_budget" in report.limits_reached
    assert report.requests_sent == len(lab.log) <= PAGE_CAP + EXTRA_REQUEST_CAP
    assert any("redirect limit" in str(p.detail) for p in report.pages)


def test_the_crawl_deadline_stops_the_scan_and_says_so(make_lab, monkeypatch):
    monkeypatch.setattr(crawl, "CRAWL_DEADLINE_S", 0.6)

    def slow() -> tuple[int, list[tuple[str, str]], bytes]:
        time.sleep(0.4)
        return page("slow")

    lab = make_lab({"/": page("".join(f"<a href='/s{i}'>{i}</a>" for i in range(8)))})
    lab.routes.update({f"/s{i}": slow for i in range(8)})
    report = run(lab)
    assert "deadline" in report.limits_reached
    assert 1 < len(report.pages) < 12  # some pages were checked, the rest never requested
    assert report.requests_sent == len(lab.log)


def test_only_plain_gets_without_cookies_or_credentials(make_lab):
    cookie = ("Set-Cookie", "sid=abc123; Path=/")
    lab = make_lab({"/": page("<a href='/hop'>h</a><a href='/b'>b</a>", cookie), "/b": page("b", cookie)})
    lab.routes["/hop"] = (302, [("Location", "/b"), cookie], b"")
    report = run(lab)
    assert report.requests_sent == len(lab.log) > 5
    for entry in lab.log:
        headers = entry["headers"]
        assert entry["method"] == "GET"
        assert "cookie" not in headers and "authorization" not in headers and "referer" not in headers
        assert headers["user-agent"] == USER_AGENT and headers["accept-encoding"] == "identity"
        assert headers.get("content-length") in (None, "0")


# ---------------------------------------------------------------- mocked network (hosted rules)
class Net:
    """A mocked public site at https://site.test with per-path pages; records each request."""

    def __init__(self, pages: dict[str, tuple[int, list[tuple[str, str]], bytes]]) -> None:
        self.pages = pages
        self.seen: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        status, headers, body = self.pages.get(request.url.path, (404, HTML, b"nope"))
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


HOSTED = {"allowed_ports": frozenset({80, 443}), "generic_errors": True}


def test_discovered_urls_follow_the_same_private_address_and_port_rules(fake_dns, monkeypatch):
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)
    net = Net(
        {
            "/": page(
                "<a href='http://evil.test/admin'>p</a><a href='http://rebind.test/'>r</a>"
                "<a href='https://site.test:22/x'>port</a><a href='http://169.254.169.254/latest'>meta</a>"
                "<a href='https://site.test/ok'>ok</a>",
                *[(k, v[0]) for k, v in GOOD.items()],
            ),
            "/ok": page("ok"),
        }
    )
    report = scan("https://site.test/", transport=net.transport, probe=ok_probe, **HOSTED)
    assert {r.headers["host"] for r in net.seen} == {"site.test"}  # no request to any other host
    assert {r.url.port for r in net.seen} == {None}
    assert report.links_skipped == 4 and "/ok" in by_path(report)


def test_a_discovered_page_that_now_resolves_to_a_private_address_is_blocked(fake_dns, monkeypatch):
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)
    net = Net({"/": page("<a href='/a'>a</a>")})
    start_handler = net.handle

    def rebinding(request: httpx.Request) -> httpx.Response:
        monkeypatch.setitem(DNS, "site.test", ["10.0.0.5"])  # the name stops pointing at a public address
        return start_handler(request)

    net.transport = httpx.MockTransport(rebinding)
    report = scan("https://site.test/", transport=net.transport, probe=ok_probe, **HOSTED)
    assert report.headers_checked and len(net.seen) == 1  # only the start page was ever requested
    blocked = [p for p in report.pages if p.outcome == "blocked"]
    assert len(blocked) == len(report.pages) - 1 and {p.detail for p in blocked} == {"this address is not allowed here"}


def test_a_failing_discovered_page_never_aborts_the_scan(fake_dns, monkeypatch):
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, headers=dict(HTML), stream=httpx.ByteStream(b"<a href='/a'>a</a>"))

    report = scan("https://site.test/", transport=httpx.MockTransport(handler), probe=ok_probe, **HOSTED)
    failed = by_path(report)["/a"]
    assert (failed.outcome, failed.status_code, failed.detail) == ("failed", None, "the site could not be reached")


def test_merged_findings_list_their_pages_and_the_weakest_page_sets_the_grade(fake_dns, monkeypatch):
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)
    good = [(k, v[0]) for k, v in GOOD.items() if k != "set-cookie"]
    no_csp = [(k, v) for k, v in good if k != "content-security-policy"]
    third_party = "<script src='https://cdn.example.net/x.js'></script>"
    net = Net(
        {
            "/": page("<a href='/a'>a</a><a href='/b'>b</a><a href='/c'>c</a>", *good),
            "/a": page(third_party, *no_csp),
            "/b": page("plain", *[(k, v) for k, v in no_csp if k not in {"x-content-type-options", "referrer-policy"}]),
            "/c": page("fine", *good),
        }
    )
    site = scan("https://site.test/", transport=net.transport, probe=ok_probe)
    single = scan("https://site.test/", transport=net.transport, probe=ok_probe, scope="page")
    assert single.grade == "A" and not single.findings
    missing = next(f for f in site.findings if f.id == "csp.missing")
    assert missing.pages == ["/a", "/b"] and missing.pages_total == 2
    assert missing.severity == "medium"  # /a loads third-party scripts, so its instance is the most severe
    assert site.grade != "A" and site.score < single.score
    assert by_path(site)["/c"].finding_ids == [] and by_path(site)["/a"].finding_ids


def test_findings_name_at_most_twenty_pages_and_count_all(fake_dns, monkeypatch):
    monkeypatch.setattr(crawl, "PAUSE_S", 0.0)
    links = "".join(f"<a href='/p{i}'>{i}</a>" for i in range(30))
    net = Net({"/": page(links, ("Content-Type", "text/html")), **{f"/p{i}": page("x") for i in range(30)}})
    report = scan("https://site.test/", transport=net.transport, probe=ok_probe)
    finding = next(f for f in report.findings if f.id == "hsts.missing")
    assert len(finding.pages or []) == 20 and finding.pages_total == 31


# ---------------------------------------------------------------- API, CLI and old reports
def test_api_scope_defaults_to_site_and_accepts_page(monkeypatch):
    seen = []
    monkeypatch.setattr(api, "scan", lambda url, **kwargs: seen.append(kwargs) or _fake_report())
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    assert client.post("/api/webcheck", json={"url": "https://site.test"}).status_code == 200
    assert client.post("/api/webcheck", json={"url": "https://site.test", "scope": "page"}).status_code == 200
    assert client.post("/api/webcheck", json={"url": "https://site.test", "scope": "everything"}).status_code == 422
    assert [k["scope"] for k in seen] == ["site", "page"]


def test_cli_checks_the_site_unless_page_only(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "scan", lambda url, **kwargs: seen.append(kwargs["scope"]) or _fake_report())
    runner = CliRunner()
    site = runner.invoke(cli.app, ["scan", "https://site.test"])
    page_only = runner.invoke(cli.app, ["scan", "https://site.test", "--page-only"])
    assert seen == ["site", "page"]
    assert NOTICE_SITE in site.output and NOTICE_PAGE in page_only.output


def test_a_report_saved_before_site_scans_still_validates():
    old = _fake_report().model_dump(
        exclude={"scope", "pages", "requests_sent", "limits_reached", "links_skipped", "sitemap_entries"}
    )
    old["findings"] = [{"id": "x.y", "severity": "low", "title": "t", "explanation": "e", "recommendation": "r"}]
    report = Report.model_validate(old)
    assert (report.scope, report.pages, report.limits_reached) == ("page", [], [])
    assert report.findings[0].pages is None and report.tls == OK_TLS
