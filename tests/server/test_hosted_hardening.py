# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted mode: concurrency caps, upload caps, login abuse limits, error handling, deletion
residue, disabled accounts, host-hash logs and caching (security review of 2026-10-19)."""

import logging
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kestrix.cli import app as cli_app
from kestrix.server.app import body_limit, create_app, hosted_body_limits
from kestrix.server.auth import host_tag
from kestrix.server.headers import HSTS
from kestrix.server.ratelimit import RateLimiter
from kestrix.server.settings import Settings, SettingsError, load_settings
from kestrix.webcheck import api as webcheck_api
from kestrix.webcheck.models import Report, Timings, TlsInfo

from .hosted_support import GOOGLE_EMAIL, ORIGIN, csrf, sign_in

MIB = 1024 * 1024
SCAN_BODY = {"url": "https://Site.example./path", "authorized": True}


def report(url: str) -> Report:
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


class BlockingScan:
    """A stand-in for ``scan`` that holds each call until released."""

    def __init__(self) -> None:
        self.started = threading.Semaphore(0)
        self.release = threading.Event()
        self.calls: list[dict[str, object]] = []

    def __call__(self, url: str, **kwargs: object) -> Report:
        self.calls.append(kwargs)
        self.started.release()
        assert self.release.wait(10)
        return report(url)


@pytest.fixture
def blocking_scan(monkeypatch):
    scan = BlockingScan()
    monkeypatch.setattr(webcheck_api, "scan", scan)
    yield scan
    scan.release.set()


def in_background(fn) -> list[httpx.Response]:
    """Start ``fn`` in a thread; the returned list receives its response when it finishes."""
    out: list[httpx.Response] = []
    threading.Thread(target=lambda: out.append(fn()), daemon=True).start()
    return out


# Concurrency


def test_one_module_request_at_a_time_per_user(hosted, providers, blocking_scan):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    first = in_background(lambda: hosted.post("/api/webcheck", json=SCAN_BODY, headers=headers))
    assert blocking_scan.started.acquire(timeout=5)
    for path, kwargs in [
        ("/api/webcheck", {"json": SCAN_BODY}),
        ("/api/forensics/url", {"json": {"url": "https://a.example"}}),
    ]:
        resp = hosted.post(path, headers=headers, **kwargs)
        assert resp.status_code == 429 and resp.json()["reason"] == "busy"
        assert resp.headers["retry-after"] == "5"
    blocking_scan.release.set()
    for _ in range(100):
        if first:
            break
        time.sleep(0.05)
    assert first[0].status_code == 200
    # The slot is free again, and the busy refusals did not use up the hourly allowance.
    assert hosted.post("/api/webcheck", json=SCAN_BODY, headers=headers).status_code == 200
    assert len(blocking_scan.calls) == 2


def test_global_cap_on_concurrent_website_checks(make_hosted, providers, blocking_scan):
    client = make_hosted(max_concurrent_webchecks=1)
    sign_in(client, providers, "google")
    headers = csrf(client)
    other = TestClient(client.app, base_url=ORIGIN)
    sign_in(other, providers, "github")
    other_headers = csrf(other)
    in_background(lambda: client.post("/api/webcheck", json=SCAN_BODY, headers=headers))
    assert blocking_scan.started.acquire(timeout=5)
    resp = other.post("/api/webcheck", json=SCAN_BODY, headers=other_headers)
    assert resp.status_code == 503 and resp.json()["reason"] == "busy" and resp.headers["retry-after"] == "5"
    # Analyses have their own cap and are not blocked by website checks.
    assert other.post("/api/forensics/url", json={"url": "https://a.example"}, headers=other_headers).status_code == 200
    blocking_scan.release.set()


def test_health_answers_while_checks_run(make_hosted, providers, blocking_scan):
    client = make_hosted(max_concurrent_webchecks=8)
    sign_in(client, providers)
    in_background(lambda: client.post("/api/webcheck", json=SCAN_BODY, headers=csrf(client)))
    assert blocking_scan.started.acquire(timeout=5)
    started = time.monotonic()
    assert client.get("/api/health").status_code == 200
    assert time.monotonic() - started < 1


# Upload caps


def test_hosted_upload_caps_are_lower_than_local():
    hosted = load_settings(
        {
            "KESTRIX_MODE": "hosted",
            "KESTRIX_PUBLIC_ORIGIN": ORIGIN,
            "KESTRIX_SESSION_PEPPER": "p" * 40,
            "KESTRIX_JWT_SECRET": "j" * 40,
            "KESTRIX_HISTORY_KEY": "A" * 43 + "=",
            "KESTRIX_GITHUB_CLIENT_ID": "id",
            "KESTRIX_GITHUB_CLIENT_SECRET": "secret",
        }
    ).hosted
    assert hosted is not None and hosted.max_mail_bytes == hosted.max_file_bytes == 10 * MIB
    limits = hosted_body_limits(hosted)
    assert limits == {"/api/forensics/file": 10 * MIB + 64 * 1024, "/api/mail/analyze": 10 * MIB + 64 * 1024}
    assert body_limit("/api/mail/analyze") == 26 * MIB and body_limit("/api/forensics/file") == 51 * MIB  # local


@pytest.mark.parametrize(("path", "field"), [("/api/mail/analyze", "m.eml"), ("/api/forensics/file", "a.bin")])
def test_hosted_uploads_over_the_cap_are_413(make_hosted, providers, path, field):
    client = make_hosted(max_mail_bytes=1000, max_file_bytes=1000)
    sign_in(client, providers)
    headers = csrf(client)
    declared = client.post(path, files={"file": (field, b"\x00" * 70_000)}, headers=headers)
    assert declared.status_code == 413 and declared.json()["reason"] == "input_too_large"

    def body():
        yield f'--x\r\nContent-Disposition: form-data; name="file"; filename="{field}"\r\n\r\n'.encode()
        for _ in range(10):
            yield b"\x00" * 10_000

    streamed = client.post(path, content=body(), headers={**headers, "content-type": "multipart/form-data; boundary=x"})
    assert streamed.status_code == 413
    small = client.post(path, files={"file": (field, b"\x00" * 1500)}, headers=headers)
    assert small.status_code == 413 and "1,000 byte limit" in small.json()["detail"]


# Website check: ports, generic errors and the host-hash log line


def test_hosted_webcheck_restricts_ports_and_hides_connection_details(hosted, providers, blocking_scan):
    blocking_scan.release.set()
    sign_in(hosted, providers)
    assert hosted.post("/api/webcheck", json=SCAN_BODY, headers=csrf(hosted)).status_code == 200
    kwargs = blocking_scan.calls[0]
    assert kwargs["allowed_ports"] == frozenset({80, 443})
    assert kwargs["generic_errors"] is True


def test_hosted_webcheck_logs_a_host_hash_not_the_host(hosted, providers, blocking_scan, hosted_env, caplog):
    blocking_scan.release.set()
    caplog.set_level(logging.INFO, logger="kestrix")
    sign_in(hosted, providers)
    assert hosted.post("/api/webcheck", json=SCAN_BODY, headers=csrf(hosted)).status_code == 200
    lines = [r.getMessage() for r in caplog.records if r.name == "kestrix.webcheck"]
    assert len(lines) == 1
    auth = hosted.app.state.auth
    tag = host_tag(auth.settings.log_salt, "site.example")
    assert lines[0] == f"webcheck user={auth.user_tag(1)} host={tag}"
    assert "site.example" not in caplog.text.lower()
    result = CliRunner().invoke(cli_app, ["hosted", "hash-host", "SITE.example"])
    assert result.exit_code == 0 and result.output.strip() == tag
    assert host_tag(auth.settings.log_salt, "https://site.example:443/x") == tag


# Sign-in abuse


def attempts(client: TestClient) -> int:
    return client.app.state.auth.store._db.execute("SELECT count(*) FROM login_attempts").fetchone()[0]


@pytest.mark.parametrize(
    "fetch",
    [
        {"sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "image"},
        {"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe"},
        {"sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty"},
    ],
)
def test_cross_site_sign_in_starts_are_refused_unless_top_level(hosted, fetch):
    for _ in range(25):
        resp = hosted.get("/api/auth/login/google", headers=fetch, follow_redirects=False)
        assert resp.status_code == 403 and resp.json()["reason"] == "cross_site_request"
    assert attempts(hosted) == 0
    # The refused requests did not use up the visitor's allowance.
    assert hosted.get("/api/auth/login/google", follow_redirects=False).status_code == 302


def test_top_level_sign_in_from_another_site_still_works(hosted):
    navigate = {"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}
    assert hosted.get("/api/auth/login/google", headers=navigate, follow_redirects=False).status_code == 302
    assert attempts(hosted) == 1


def test_ipv6_clients_share_a_limit_per_64(hosted_env, monkeypatch, providers):
    monkeypatch.setenv("KESTRIX_CLIENT_IP_HEADER", "Fly-Client-IP")
    client = TestClient(create_app(provider_transport=httpx.MockTransport(providers.handler)), base_url=ORIGIN)
    for i in range(20):
        ip = {"fly-client-ip": f"2001:db8:1:2::{i + 1:x}"}
        assert client.get("/api/auth/login/github", headers=ip, follow_redirects=False).status_code == 302
    rotated = client.get(
        "/api/auth/login/github", headers={"fly-client-ip": "2001:db8:1:2:ffff::9"}, follow_redirects=False
    )
    assert rotated.status_code == 429
    other = client.get("/api/auth/login/github", headers={"fly-client-ip": "2001:db8:1:3::1"}, follow_redirects=False)
    assert other.status_code == 302  # another /64


def test_limiter_eviction_keeps_blocked_keys_and_stays_fast():
    limiter = RateLimiter(max_keys=10_000)
    for _ in range(10):
        limiter.hit("login:198.51.100.7", 10, 600)
    assert limiter.hit("login:198.51.100.7", 10, 600) is not None
    started = time.perf_counter()
    for i in range(50_000):
        limiter.hit(f"login:2001:db8::{i:x}/64", 10, 600)
    assert time.perf_counter() - started < 2  # amortized, not a full scan per request
    assert len(limiter) <= 10_000
    assert limiter.hit("login:198.51.100.7", 10, 600) is not None  # the flood did not reset it


def test_limiter_drops_stale_and_least_recent_keys_first():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0], max_keys=10)

    def hit(key: str, window: float = 60) -> None:
        now[0] += 1
        limiter.hit(key, 5, window)

    for i in range(5):
        hit(f"old{i}")
    now[0] += 100  # old* have no hit inside their window now
    for i in range(5):
        hit(f"new{i}")
    hit("new0")  # new0 is now the most recently requested of new*
    hit("extra")  # over the cap: the stale keys go
    assert len(limiter) == 6
    for i in range(5):
        hit(f"more{i}", 600)  # 11 keys: the least recently requested go, across window lengths
    keys = {key for entries in limiter._windows.values() for key in entries}
    assert not any(key.startswith("old") for key in keys)
    assert {"new1", "new2"}.isdisjoint(keys) and {"new0", "extra", "more4"} <= keys
    assert len(limiter) <= 10


# Errors, caching and the API schema


def test_unexpected_errors_are_json_500_with_security_headers(hosted, providers, monkeypatch, caplog):
    def boom(url, **kwargs):
        raise RuntimeError("detail that quotes secret-user-input")

    monkeypatch.setattr(webcheck_api, "scan", boom)
    sign_in(hosted, providers)
    caplog.set_level(logging.INFO, logger="kestrix")
    resp = hosted.post("/api/webcheck", json=SCAN_BODY, headers=csrf(hosted))
    assert resp.status_code == 500
    assert resp.json() == {"reason": "internal_error", "detail": "unexpected error"}
    assert resp.headers["strict-transport-security"] == HSTS
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["cache-control"] == "no-store"
    assert "secret-user-input" not in caplog.text and "RuntimeError" in caplog.text


def test_unexpected_errors_in_local_mode_keep_the_headers(monkeypatch):
    monkeypatch.setattr(webcheck_api, "scan", lambda url, **kwargs: 1 / 0)
    local = TestClient(create_app(extra_hosts=frozenset({"testserver"}), server_settings=Settings()))
    resp = local.post("/api/webcheck", json={"url": "https://a.example"})
    assert resp.status_code == 500 and resp.json()["reason"] == "internal_error"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "strict-transport-security" not in resp.headers and "cache-control" not in resp.headers


def test_every_hosted_api_response_is_no_store(hosted):
    for resp in [
        hosted.get("/api/health"),
        hosted.get("/api/webcheck"),  # 401
        hosted.get("/api/detect/cases"),  # 404
        hosted.get("/api/health", headers={"host": "kestrix.example.evil.example"}),  # 421
    ]:
        assert resp.headers["cache-control"] == "no-store", resp.status_code
    assert "no-store" not in hosted.get("/welcome").headers.get("cache-control", "")


# Accounts: deletion residue, ids, disabled accounts


def test_deletion_leaves_no_residue_and_ids_are_not_reused(hosted, providers, hosted_env):
    db = hosted.app.state.auth.store._db
    assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    sign_in(hosted, providers, "github")
    sign_in(hosted, providers, "google")
    google_id = db.execute("SELECT id FROM users WHERE email = ?", (GOOGLE_EMAIL,)).fetchone()[0]
    headers = csrf(hosted)
    assert hosted.post("/api/forensics/url", json={"url": "https://a.example"}, headers=headers).status_code == 200
    limiter = next(m.kwargs["limiter"] for m in hosted.app.user_middleware if "limiter" in m.kwargs)
    assert len(limiter) > 0 and any(f"analysis:{google_id}" in e for e in limiter._windows.values())
    assert hosted.delete("/api/auth/account", headers=headers).status_code == 204
    assert not any(f"analysis:{google_id}" in e for e in limiter._windows.values())
    files = [Path(hosted_env["KESTRIX_DB"]), Path(hosted_env["KESTRIX_DB"] + "-wal")]
    data = b"".join(path.read_bytes() for path in files if path.exists())
    assert GOOGLE_EMAIL.encode() not in data
    hosted.cookies.clear()
    sign_in(hosted, providers, "google")
    new_id = db.execute("SELECT id FROM users WHERE email = ?", (GOOGLE_EMAIL,)).fetchone()[0]
    assert new_id > google_id


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE users (id INTEGER PRIMARY KEY, provider TEXT, subject TEXT)",
        # ADR 0004's opaque-session table, before refresh families (ADR 0007)
        "CREATE TABLE sessions (id_hash TEXT PRIMARY KEY, user_id INTEGER, csrf_token_hash TEXT, "
        "created_at INTEGER, last_seen_at INTEGER, expires_at INTEGER)",
    ],
)
def test_a_database_with_an_old_schema_is_refused(hosted_env, ddl):
    path = Path(hosted_env["KESTRIX_DB"])
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as db:
        db.execute(ddl)
    with pytest.raises(SettingsError, match="older schema"):
        create_app()


def test_disabled_accounts_cannot_sign_in_and_their_sessions_end(hosted, providers, clock, caplog):
    sign_in(hosted, providers)
    assert hosted.get("/api/auth/me").json()["signed_in"]
    runner = CliRunner()
    result = runner.invoke(cli_app, ["hosted", "disable-user", "--email", GOOGLE_EMAIL.upper()])
    assert result.exit_code == 0 and "Disabled 1 account" in result.output
    # The operator command is another process as far as the server is concerned: its cached check of
    # the refresh family lasts at most 30 seconds (ADR 0007).
    assert hosted.get("/api/auth/me").json()["signed_in"]
    clock.advance(31)
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}
    assert hosted.post("/api/auth/refresh", headers={"x-csrf-token": "x"}).status_code == 401
    caplog.set_level(logging.INFO, logger="kestrix")
    resp = sign_in(hosted, providers)
    assert resp.headers["location"] == "/welcome?signin=failed"
    assert "reason=account_disabled" in caplog.text
    assert runner.invoke(cli_app, ["hosted", "enable-user", "--email", GOOGLE_EMAIL]).exit_code == 0
    assert sign_in(hosted, providers).headers["location"] == "/app"
    assert runner.invoke(cli_app, ["hosted", "disable-user", "--email", "nobody@mail.example"]).exit_code == 1


def test_operator_commands_need_hosted_settings():
    result = CliRunner().invoke(cli_app, ["hosted", "hash-host", "site.example"])
    assert result.exit_code == 2 and "not configured" in result.output
