# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode sign-in (Google OIDC, GitHub OAuth), sessions, CSRF and account deletion."""

import hashlib
import sqlite3
import stat
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from kestrix.server.auth import AuthFailed, ProviderClient, pkce_challenge, safe_next

from .hosted_support import (
    GITHUB_ACCESS,
    GITHUB_EMAIL,
    GITHUB_ID,
    GITHUB_SECRET,
    GOOGLE_EMAIL,
    GOOGLE_ID,
    GOOGLE_SECRET,
    csrf,
    sign_in,
    start_login,
)

FAILED = "/welcome?signin=failed"
DAY = 24 * 3600


def db_rows(env, sql, *args):
    with sqlite3.connect(env["KESTRIX_DB"]) as db:
        return db.execute(sql, args).fetchall()


def session_cookie(resp: httpx.Response) -> str:
    return next(v for v in resp.headers.get_list("set-cookie") if v.startswith("__Host-kx_session="))


# Google


def test_google_login_redirect_carries_pkce_state_and_nonce(hosted):
    query = start_login(hosted, "google", next="/app/forensics")
    assert query["client_id"] == GOOGLE_ID
    assert query["redirect_uri"] == "https://kestrix.example/api/auth/callback/google"
    assert query["response_type"] == "code"
    assert query["scope"] == "openid email profile"
    assert query["code_challenge_method"] == "S256"
    assert len(query["state"]) >= 43 and len(query["nonce"]) >= 43
    login = hosted.get("/api/auth/login/google", follow_redirects=False)
    assert login.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert login.headers["cache-control"] == "no-store"


def test_google_sign_in_happy_path(hosted, providers, hosted_env):
    resp = sign_in(hosted, providers, "google", next="/app/mail")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/app/mail"
    form = providers.form()
    assert [str(r.url) for r in providers.requests] == ["https://oauth2.googleapis.com/token"]
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code"
    assert form["client_id"] == GOOGLE_ID and form["client_secret"] == GOOGLE_SECRET
    assert form["redirect_uri"] == "https://kestrix.example/api/auth/callback/google"
    attempts = db_rows(hosted_env, "SELECT COUNT(*) FROM login_attempts")
    assert attempts == [(0,)]  # used once and gone
    me = hosted.get("/api/auth/me")
    assert me.headers["cache-control"] == "no-store"
    body = me.json()
    assert body["signed_in"] is True
    assert body["user"] == {"display_name": "Ada Lovelace", "email": GOOGLE_EMAIL, "provider": "google"}
    assert len(body["csrf_token"]) >= 43


def test_pkce_verifier_sent_matches_the_challenge(hosted, providers):
    query = start_login(hosted, "google")
    providers.nonce = query["nonce"]
    hosted.get("/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False)
    verifier = providers.form()["code_verifier"]
    assert 43 <= len(verifier) <= 128
    assert pkce_challenge(verifier) == query["code_challenge"]


def test_session_cookie_attributes(hosted, providers):
    cookie = session_cookie(sign_in(hosted, providers)).lower()
    attributes = {part.strip().split("=")[0] for part in cookie.split(";")}
    assert {"secure", "httponly", "path", "samesite", "max-age"} <= attributes
    assert "path=/;" in cookie + ";" and "samesite=lax" in cookie
    assert "domain" not in attributes


def _flow(hosted, providers, **overrides):
    providers.google_overrides = overrides
    return sign_in(hosted, providers)


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"aud": [GOOGLE_ID, "someone-else"], "azp": "someone-else"},
        {"iss": "https://accounts.evil.example"},
        {"nonce": "not-the-nonce"},
        {"email_verified": False},
        {"email_verified": "true"},
        {"exp": 1},
        {"iat": 4_000_000_000},
        {"email": None},
    ],
)
def test_bad_id_tokens_fail_closed(hosted, providers, overrides):
    resp = _flow(hosted, providers, **overrides)
    assert resp.status_code == 303 and resp.headers["location"] == FAILED
    assert "__Host-kx_session=" not in resp.headers.get("set-cookie", "")
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}


def test_nonce_comes_from_the_attempt(hosted, providers):
    query = start_login(hosted, "google")
    providers.nonce = start_login(hosted, "google")["nonce"]  # a different, valid-looking nonce
    resp = hosted.get(
        "/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False
    )
    assert resp.headers["location"] == FAILED


def test_unknown_state_fails(hosted, providers):
    start_login(hosted)
    resp = hosted.get("/api/auth/callback/google", params={"code": "c", "state": "forged"}, follow_redirects=False)
    assert resp.headers["location"] == FAILED
    assert providers.requests == []  # never reached the token endpoint


def test_state_is_single_use(hosted, providers):
    query = start_login(hosted)
    providers.nonce = query["nonce"]
    params = {"code": "c", "state": query["state"]}
    hosted.cookies.set("__Host-kx_login", query["state"], domain="kestrix.example")
    first = hosted.get("/api/auth/callback/google", params=params, follow_redirects=False)
    assert first.headers["location"] == "/app"
    hosted.cookies.set("__Host-kx_login", query["state"], domain="kestrix.example")
    replay = hosted.get("/api/auth/callback/google", params=params, follow_redirects=False)
    assert replay.headers["location"] == FAILED


def test_state_must_be_bound_to_the_browser(hosted, providers):
    """A callback link with someone else's state (login CSRF) fails without the login cookie."""
    query = start_login(hosted)
    providers.nonce = query["nonce"]
    hosted.cookies.clear()
    resp = hosted.get(
        "/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False
    )
    assert resp.headers["location"] == FAILED


def test_state_for_another_provider_fails(hosted, providers):
    query = start_login(hosted, "github")
    resp = hosted.get(
        "/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False
    )
    assert resp.headers["location"] == FAILED


def test_expired_attempt_fails(hosted, providers, clock):
    query = start_login(hosted)
    providers.nonce = query["nonce"]
    clock.advance(601)
    resp = hosted.get(
        "/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False
    )
    assert resp.headers["location"] == FAILED


def test_provider_error_and_token_failure_fail(hosted, providers):
    query = start_login(hosted)
    denied = hosted.get(
        "/api/auth/callback/google", params={"error": "access_denied", "state": query["state"]}, follow_redirects=False
    )
    assert denied.headers["location"] == FAILED
    providers.token_status = 400
    assert sign_in(hosted, providers).headers["location"] == FAILED


def test_unknown_provider_is_404(hosted):
    assert hosted.get("/api/auth/login/facebook", follow_redirects=False).status_code == 404
    assert hosted.get("/api/auth/callback/facebook", follow_redirects=False).headers["location"] == FAILED


def test_providers_lists_enabled_ones(hosted):
    assert hosted.get("/api/auth/providers").json() == {"providers": ["google", "github"]}


# GitHub


def test_github_sign_in_happy_path(hosted, providers, hosted_env):
    query = start_login(hosted, "github")
    assert "nonce" not in query
    assert query["code_challenge_method"] == "S256"
    assert query["scope"] == "read:user user:email"
    resp = hosted.get(
        "/api/auth/callback/github", params={"code": "gh", "state": query["state"]}, follow_redirects=False
    )
    assert resp.headers["location"] == "/app"
    form = providers.form()
    assert form["client_id"] == GITHUB_ID and form["client_secret"] == GITHUB_SECRET
    assert pkce_challenge(form["code_verifier"]) == query["code_challenge"]
    api_calls = [r for r in providers.requests if r.url.host == "api.github.com"]
    assert [r.headers["authorization"] for r in api_calls] == [f"Bearer {GITHUB_ACCESS}"] * 2
    assert hosted.get("/api/auth/me").json()["user"] == {
        "display_name": "Octo Cat",
        "email": GITHUB_EMAIL,
        "provider": "github",
    }
    assert db_rows(hosted_env, "SELECT provider, subject FROM users") == [("github", "4242")]


@pytest.mark.parametrize(
    "emails",
    [
        [],
        [{"email": "octo@mail.example", "primary": True, "verified": False}],
        [{"email": "octo@mail.example", "primary": False, "verified": True}],
    ],
)
def test_github_without_a_verified_primary_email_fails(hosted, providers, emails):
    providers.github_emails = emails
    assert sign_in(hosted, providers, "github").headers["location"] == FAILED


# Redirect target


@pytest.mark.parametrize(
    "target",
    ["//evil.example", "https://evil.example", "/\\evil.example", "\\\\evil.example", "/\t/evil.example", "app", ""],
)
def test_open_redirects_are_refused(hosted, providers, target):
    assert safe_next(target) is None
    resp = sign_in(hosted, providers, next=target)
    assert resp.headers["location"] == "/app"


def test_relative_next_is_kept():
    assert safe_next("/app/webcheck?tab=1") == "/app/webcheck?tab=1"


# Sessions


def test_session_id_is_stored_only_as_a_keyed_hash(hosted, providers, hosted_env):
    raw = session_cookie(sign_in(hosted, providers)).split(";")[0].split("=", 1)[1]
    hosted.app.state.auth.store.close()  # flush the WAL into the main file
    db_path = Path(hosted_env["KESTRIX_DB"])
    data = b"".join(p.read_bytes() for p in db_path.parent.iterdir())
    assert raw.encode() not in data
    assert hashlib.sha256(raw.encode()).hexdigest().encode() not in data  # keyed, not a bare hash
    assert hosted.app.state.auth._csrf_token(raw).encode() not in data


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_database_file_and_directory_are_private(hosted, hosted_env):
    db_path = Path(hosted_env["KESTRIX_DB"])
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700


def test_idle_expiry(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    clock.advance(7 * DAY - 60)
    assert hosted.get("/api/auth/me").json()["signed_in"]  # still within 7 days; refreshed
    clock.advance(7 * DAY - 60)
    assert hosted.get("/api/auth/me").json()["signed_in"]
    clock.advance(7 * DAY)
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(0,)]


def test_absolute_expiry_despite_activity(hosted, providers, clock):
    sign_in(hosted, providers)
    for _ in range(4):
        clock.advance(6 * DAY)
        assert hosted.get("/api/auth/me").json()["signed_in"]
    clock.advance(6 * DAY + 1)  # day 30
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}


def test_last_seen_slides_at_most_every_five_minutes(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    (created,) = db_rows(hosted_env, "SELECT last_seen_at FROM sessions")[0]
    clock.advance(120)
    hosted.get("/api/auth/me")
    assert db_rows(hosted_env, "SELECT last_seen_at FROM sessions") == [(created,)]
    clock.advance(240)
    hosted.get("/api/auth/me")
    assert db_rows(hosted_env, "SELECT last_seen_at FROM sessions") == [(created + 360,)]


def test_signing_in_again_rotates_the_session(hosted, providers, hosted_env):
    first = session_cookie(sign_in(hosted, providers))
    second = session_cookie(sign_in(hosted, providers))
    assert first.split(";")[0] != second.split(";")[0]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(1,)]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM users") == [(1,)]


# CSRF, logout and account deletion


def test_state_changing_requests_need_the_csrf_header(hosted, providers):
    sign_in(hosted, providers)
    url = {"url": "http://paypa1-login.example.top/verify"}
    assert hosted.post("/api/forensics/url", json=url).json()["reason"] == "csrf_failed"
    wrong = hosted.post("/api/forensics/url", json=url, headers={"x-csrf-token": "x" * 43})
    assert wrong.status_code == 403 and wrong.json()["reason"] == "csrf_failed"
    assert hosted.post("/api/forensics/url", json=url, headers=csrf(hosted)).status_code == 200


def test_csrf_token_from_another_session_is_refused(hosted, providers, hosted_env):
    sign_in(hosted, providers)
    old_token = csrf(hosted)
    sign_in(hosted, providers)
    resp = hosted.post("/api/forensics/url", json={"url": "https://a.example"}, headers=old_token)
    assert resp.status_code == 403


def test_logout_needs_csrf_and_ends_the_session(hosted, providers, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    assert hosted.post("/api/auth/logout").status_code == 403
    resp = hosted.post("/api/auth/logout", headers=headers)
    assert resp.status_code == 204
    assert 'kx_session=""' in resp.headers["set-cookie"] and "max-age=0" in resp.headers["set-cookie"].lower()
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(0,)]
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}


def test_logout_without_a_session_is_harmless(hosted):
    assert hosted.post("/api/auth/logout").status_code == 204


def test_account_deletion_needs_csrf_and_removes_user_and_all_sessions(hosted, providers, hosted_env):
    other_device = TestClient(hosted.app, base_url=str(hosted.base_url))
    sign_in(other_device, providers)
    sign_in(hosted, providers)
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(2,)]
    assert hosted.delete("/api/auth/account").status_code == 403
    assert hosted.delete("/api/auth/account", headers=csrf(hosted)).status_code == 204
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM users") == [(0,)]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(0,)]
    assert other_device.get("/api/auth/me").json() == {"signed_in": False}


def test_account_deletion_needs_a_session(hosted):
    resp = hosted.delete("/api/auth/account")
    assert resp.status_code == 401 and resp.json()["reason"] == "sign_in_required"


# Outbound provider requests


@pytest.mark.parametrize(
    "url",
    ["https://evil.example/token", "http://github.com/login/oauth/access_token", "https://github.com:8443/x"],
)
def test_provider_client_only_reaches_allowlisted_https_hosts(url):
    calls = []
    client = ProviderClient(httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json={})))
    with pytest.raises(AuthFailed, match="provider_host_not_allowed"):
        client.request("GET", url)
    assert calls == []


def test_provider_client_does_not_follow_redirects_or_read_huge_bodies():
    redirect = ProviderClient(
        httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://evil.example/"}))
    )
    with pytest.raises(AuthFailed, match="provider_http_error"):
        redirect.request("GET", "https://api.github.com/user")
    huge = ProviderClient(httpx.MockTransport(lambda r: httpx.Response(200, content=b"[" + b"1," * 40_000 + b"1]")))
    with pytest.raises(AuthFailed, match="provider_response_too_large"):
        huge.request("GET", "https://api.github.com/user")
