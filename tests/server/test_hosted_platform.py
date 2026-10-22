# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted mode: host and origin rules, route gating, rate limits, website-check rules and logs."""

import logging

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from kestrix.server.app import create_app
from kestrix.server.headers import HSTS
from kestrix.server.ratelimit import RateLimiter, client_ip
from kestrix.server.settings import Settings
from kestrix.webcheck import api as webcheck_api
from kestrix.webcheck.models import Report, Timings, TlsInfo

from .hosted_support import (
    ACCESS,
    GOOGLE_ACCESS,
    GOOGLE_EMAIL,
    JWT_SECRET,
    ORIGIN,
    PEPPER,
    REFRESH,
    cookie_value,
    csrf,
    refresh,
    sign_in,
)

URL_BODY = {"url": "http://paypa1-login.example.top/verify"}


def test_only_the_public_host_is_served(hosted):
    assert hosted.get("/api/health").status_code == 200
    for host in ["localhost", "127.0.0.1:8765", "[::1]", "attacker.example", "kestrix.example.evil.example"]:
        resp = hosted.get("/api/health", headers={"host": host})
        assert resp.status_code == 421, host
        assert resp.headers["strict-transport-security"] == HSTS


@pytest.mark.parametrize(
    "origin", ["https://evil.example", "http://kestrix.example", "https://kestrix.example:8443", "null"]
)
def test_writes_from_any_other_origin_are_refused(hosted, providers, origin):
    sign_in(hosted, providers)
    headers = {**csrf(hosted), "origin": origin}
    resp = hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    assert resp.status_code == 403 and resp.json()["reason"] == "cross_site_request"


def test_writes_from_the_public_origin_are_allowed(hosted, providers):
    sign_in(hosted, providers)
    headers = {**csrf(hosted), "origin": ORIGIN, "sec-fetch-site": "same-origin"}
    assert hosted.post("/api/forensics/url", json=URL_BODY, headers=headers).status_code == 200


def test_hsts_and_existing_headers_only_in_hosted_mode(hosted):
    resp = hosted.get("/api/health")
    assert (
        resp.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    )  # preload is the owner's choice
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert hosted.get("/api/webcheck").headers["strict-transport-security"] == HSTS  # on refusals too
    local = TestClient(create_app(extra_hosts=frozenset({"testserver"}), server_settings=Settings()))
    resp = local.get("/api/health")
    assert resp.status_code == 200 and "mode" not in resp.json()
    assert "strict-transport-security" not in resp.headers


def test_health_lists_hosted_modules_and_mode(hosted):
    body = hosted.get("/api/health").json()
    assert body["mode"] == "hosted"
    assert body["modules"] == ["forensics", "webcheck", "mail"]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/detect/cases"),
        ("POST", "/api/detect/run"),
        ("POST", "/api/detect/cases/c00-healthy-control/run"),
        ("POST", "/api/bitcoin/scan"),
        ("GET", "/api/bitcoin/migration/p2pkh"),
        ("GET", "/api/settings"),
        ("PUT", "/api/settings/anthropic-key"),
    ],
)
def test_local_only_modules_are_not_found(hosted, providers, method, path):
    anonymous = hosted.request(method, path, json={})
    assert anonymous.status_code == 404 and anonymous.json()["reason"] == "not_found"
    sign_in(hosted, providers)
    signed_in = hosted.request(method, path, json={}, headers=csrf(hosted))
    assert signed_in.status_code == 404 and signed_in.json()["reason"] == "not_found"


def test_only_hosted_routes_are_mounted(hosted):
    paths = hosted.app.openapi()["paths"]  # generated in-process; not served over HTTP
    local_only = [p for p in paths if p.startswith(("/api/detect", "/api/bitcoin", "/api/settings"))]
    assert local_only == ["/api/settings/history"]  # the result-history setting is per user (ADR 0008)
    assert "/api/auth/me" in paths and "/api/webcheck" in paths


def test_openapi_schema_is_not_served_in_hosted_mode(hosted, providers):
    assert hosted.get("/api/openapi.json").status_code == 401  # private by default, like any unknown route
    sign_in(hosted, providers)
    resp = hosted.get("/api/openapi.json")
    assert resp.status_code == 404 and resp.json()["reason"] == "not_found"
    local = TestClient(create_app(extra_hosts=frozenset({"testserver"}), server_settings=Settings()))
    assert "/api/webcheck" in local.get("/api/openapi.json").json()["paths"]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/webcheck"),
        ("POST", "/api/forensics/url"),
        ("POST", "/api/forensics/file"),
        ("POST", "/api/mail/analyze"),
        ("GET", "/api/anything-new"),
    ],
)
def test_module_routes_need_sign_in(hosted, method, path):
    resp = hosted.request(method, path, json={"url": "https://a.example"})
    assert resp.status_code == 401
    assert resp.json()["reason"] == "sign_in_required"


def test_the_dashboard_is_public(hosted):
    assert hosted.get("/welcome").status_code in {200, 503}  # 503 only when the bundle is not built


def test_signed_in_users_can_use_the_modules(hosted, providers):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    assert hosted.post("/api/forensics/url", json=URL_BODY, headers=headers).status_code == 200
    eml = b"From: a@mail.example\r\nTo: b@mail.example\r\nSubject: hi\r\n\r\nhello\r\n"
    files = {"file": ("m.eml", eml, "message/rfc822")}
    assert hosted.post("/api/mail/analyze", files=files, headers=headers).status_code == 200
    files = {"file": ("a.txt", b"hello", "text/plain")}
    assert hosted.post("/api/forensics/file", files=files, headers=headers).status_code == 200


# Rate limits


def test_sign_in_routes_are_rate_limited_per_ip(hosted):
    for _ in range(20):
        assert hosted.get("/api/auth/login/google", follow_redirects=False).status_code == 302
    resp = hosted.get("/api/auth/login/google", follow_redirects=False)
    assert resp.status_code == 429
    assert resp.json()["reason"] == "rate_limited"
    assert 1 <= int(resp.headers["retry-after"]) <= 600


def test_analyses_are_rate_limited_per_user(hosted, providers):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    for _ in range(120):
        assert hosted.post("/api/forensics/url", json=URL_BODY, headers=headers).status_code == 200
    resp = hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    assert resp.status_code == 429 and resp.json()["reason"] == "rate_limited"
    assert int(resp.headers["retry-after"]) > 0
    files = {"file": ("m.eml", b"Subject: x\r\n\r\nx", "message/rfc822")}
    assert hosted.post("/api/mail/analyze", files=files, headers=headers).status_code == 429  # same bucket


def test_rate_limiter_window_slides():
    now = [1000.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert [limiter.hit("k", 2, 60) for _ in range(2)] == [None, None]
    assert limiter.hit("k", 2, 60) == 60
    now[0] += 30
    assert limiter.hit("k", 2, 60) == 30
    now[0] += 31
    assert limiter.hit("k", 2, 60) is None
    assert limiter.hit("other", 2, 60) is None


def test_rate_limiter_memory_is_bounded():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0], max_keys=3)
    for key in "abcdef":
        limiter.hit(key, 5, 60)
    assert len(limiter) <= 3


def _request(peer: str, forwarded: list[str]) -> Request:
    headers = [(b"x-forwarded-for", value.encode()) for value in forwarded]
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


def test_client_ip_uses_the_socket_unless_proxy_headers_are_trusted():
    request = _request("10.0.0.5", ["198.51.100.7, 203.0.113.9"])
    assert client_ip(request, trust_proxy_headers=False) == "10.0.0.5"
    assert client_ip(request, trust_proxy_headers=True) == "203.0.113.9"  # right-most, added by our proxy
    assert client_ip(_request("10.0.0.5", ["1.1.1.1", "203.0.113.10"]), trust_proxy_headers=True) == "203.0.113.10"
    assert client_ip(_request("10.0.0.5", ["not-an-ip"]), trust_proxy_headers=True) == "10.0.0.5"


def test_client_ip_header_is_read_only_when_configured_and_well_formed():
    """Behind Fly every request comes from the proxy; Fly-Client-IP carries the real client."""

    def req(*values: str) -> Request:
        headers = [(b"fly-client-ip", value.encode()) for value in values]
        return Request({"type": "http", "headers": headers, "client": ("172.16.0.2", 1234)})

    assert client_ip(req("198.51.100.7"), trust_proxy_headers=False, client_ip_header="fly-client-ip") == "198.51.100.7"
    assert client_ip(req("198.51.100.7"), trust_proxy_headers=False) == "172.16.0.2"  # not configured: ignored
    assert client_ip(req("not-an-ip"), trust_proxy_headers=False, client_ip_header="fly-client-ip") == "172.16.0.2"
    # Two copies means something upstream did not overwrite it: fall back to the socket peer.
    assert (
        client_ip(req("1.1.1.1", "2.2.2.2"), trust_proxy_headers=False, client_ip_header="fly-client-ip")
        == "172.16.0.2"
    )


# Website check


@pytest.fixture
def fake_scan(monkeypatch):
    calls = []

    def scan(url, **kwargs):
        calls.append((url, kwargs))
        return Report(
            requested_url=url,
            final_url=url,
            status_code=200,
            headers_checked=True,
            tls=TlsInfo(host="site.example", status="ok"),
            grade="A",
            score=100,
            redirect_chain=[],
            findings=[],
            timings=Timings(total_ms=1, http_ms=1, tls_ms=0),
        )

    monkeypatch.setattr(webcheck_api, "scan", scan)
    return calls


def test_webcheck_requires_the_authorization_confirmation(hosted, providers, fake_scan):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    resp = hosted.post("/api/webcheck", json={"url": "https://site.example"}, headers=headers)
    assert resp.status_code == 400 and "authorized" in resp.json()["detail"]
    resp = hosted.post("/api/webcheck", json={"url": "https://site.example", "authorized": False}, headers=headers)
    assert resp.status_code == 400
    assert fake_scan == []
    ok = hosted.post("/api/webcheck", json={"url": "https://site.example", "authorized": True}, headers=headers)
    assert ok.status_code == 200
    assert fake_scan[0][1]["allow_private"] is False


def test_webcheck_scope_defaults_to_the_whole_site_and_is_validated(hosted, providers, fake_scan):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    body = {"url": "https://site.example", "authorized": True}
    assert hosted.post("/api/webcheck", json=body, headers=headers).status_code == 200
    assert hosted.post("/api/webcheck", json={**body, "scope": "page"}, headers=headers).status_code == 200
    assert hosted.post("/api/webcheck", json={**body, "scope": "all"}, headers=headers).status_code == 422
    assert [call[1]["scope"] for call in fake_scan] == ["site", "page"]


def test_webcheck_refuses_private_targets_in_hosted_mode(hosted, providers, fake_scan):
    sign_in(hosted, providers)
    body = {"url": "http://10.0.0.1/", "authorized": True, "allow_private": True}
    resp = hosted.post("/api/webcheck", json=body, headers=csrf(hosted))
    assert resp.status_code == 400 and resp.json()["reason"] == "invalid_input"
    assert fake_scan == []


def test_webcheck_names_the_abuse_contact(hosted_env, monkeypatch, providers, fake_scan):
    monkeypatch.setenv("KESTRIX_ABUSE_CONTACT", "abuse@kestrix.example")
    client = TestClient(create_app(provider_transport=httpx.MockTransport(providers.handler)), base_url=ORIGIN)
    sign_in(client, providers)
    body = {"url": "https://site.example", "authorized": True}
    assert client.post("/api/webcheck", json=body, headers=csrf(client)).status_code == 200
    agent = fake_scan[0][1]["agent"]
    assert agent.startswith("kestrix-webcheck/") and "abuse@kestrix.example" in agent


def test_webcheck_is_rate_limited_per_user(hosted, providers, fake_scan):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    body = {"url": "https://site.example", "authorized": True, "scope": "page"}
    for _ in range(20):
        assert hosted.post("/api/webcheck", json=body, headers=headers).status_code == 200
    resp = hosted.post("/api/webcheck", json=body, headers=headers)
    assert resp.status_code == 429 and "retry-after" in resp.headers


def test_whole_site_checks_have_a_tighter_hourly_limit(hosted, providers, fake_scan):
    """One site scan sends up to 65 requests, so an account gets 5 an hour; single-page checks go on."""
    sign_in(hosted, providers)
    headers = csrf(hosted)
    body = {"url": "https://site.example", "authorized": True}
    for _ in range(5):
        assert hosted.post("/api/webcheck", json=body, headers=headers).status_code == 200
    resp = hosted.post("/api/webcheck", json=body, headers=headers)
    assert resp.status_code == 429 and resp.json()["reason"] == "rate_limited"
    assert "check just this page" in resp.json()["detail"]
    assert hosted.post("/api/webcheck", json={**body, "scope": "page"}, headers=headers).status_code == 200
    assert [call[1]["scope"] for call in fake_scan] == ["site"] * 5 + ["page"]


# Logs


def test_logs_hold_no_personal_data_tokens_or_queries(hosted, providers, clock, caplog):
    caplog.set_level(logging.DEBUG, logger="kestrix")
    resp = sign_in(hosted, providers, next="/app/secret-next-path")
    access, first_refresh = cookie_value(resp, ACCESS), cookie_value(resp, REFRESH)
    token = csrf(hosted)
    clock.advance(901)
    rotated = refresh(hosted, token)
    assert rotated.status_code == 200
    new_access, new_refresh = cookie_value(rotated, ACCESS), cookie_value(rotated, REFRESH)
    stolen = TestClient(hosted.app, base_url=ORIGIN)
    stolen.cookies.set(REFRESH, first_refresh, domain="kestrix.example")
    clock.advance(11)  # past the refresh grace window
    assert refresh(stolen, token).status_code == 401  # reuse: logged as a security event
    hosted.cookies.clear()
    sign_in(hosted, providers)
    token = csrf(hosted)
    hosted.post("/api/forensics/url?probe=query-value", json={"url": "https://leak.example/x"}, headers=token)
    hosted.post("/api/forensics/file", files={"file": ("secret-name.pdf", b"%PDF-1.4")}, headers=token)
    providers.google_overrides = {"aud": "wrong"}
    sign_in(hosted, providers)
    text = caplog.text
    lines = [r.getMessage() for r in caplog.records if r.name == "kestrix.access"]
    assert any(line.startswith("POST /api/forensics/url 200 ") for line in lines)
    assert any(line.startswith("GET /api/auth/callback/{provider} 303 ") for line in lines)
    assert "reason=id_token_wrong_audience" in text
    assert "refresh token reuse detected; family revoked user=" in text
    for secret in [
        GOOGLE_EMAIL,
        GOOGLE_ACCESS,
        access,
        first_refresh,
        new_access,
        new_refresh,
        JWT_SECRET,
        PEPPER,
        token["x-csrf-token"],
        "auth-code",
        "query-value",
        "leak.example",
        "secret-name",
        "secret-next-path",
        "state=",
        "Ada Lovelace",
    ]:
        assert secret not in text, secret
    user_tags = {line.rsplit("user=", 1)[1] for line in lines if "user=-" not in line}
    assert len(user_tags) == 1 and len(next(iter(user_tags))) == 16
