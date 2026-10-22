# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode sign-in (Google OIDC, GitHub OAuth), refresh families, CSRF and account deletion.

The access-token (JWT) checks themselves are in ``test_hosted_tokens.py``."""

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
    ACCESS,
    GITHUB_ACCESS,
    GITHUB_EMAIL,
    GITHUB_ID,
    GITHUB_SECRET,
    GOOGLE_EMAIL,
    GOOGLE_ID,
    GOOGLE_SECRET,
    REFRESH,
    cookie_value,
    csrf,
    refresh,
    set_cookie,
    sign_in,
    start_login,
)

FAILED = "/welcome?signin=failed"
DAY = 24 * 3600


def db_rows(env, sql, *args):
    with sqlite3.connect(env["KESTRIX_DB"]) as db:
        return db.execute(sql, args).fetchall()


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
    assert resp.headers["location"] == "/app/mail?welcome=created"  # a new account, created through Log in
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
    assert body["access_expires_at"] == int(providers.clock.now) + 900


def test_pkce_verifier_sent_matches_the_challenge(hosted, providers):
    query = start_login(hosted, "google")
    providers.nonce = query["nonce"]
    hosted.get("/api/auth/callback/google", params={"code": "c", "state": query["state"]}, follow_redirects=False)
    verifier = providers.form()["code_verifier"]
    assert 43 <= len(verifier) <= 128
    assert pkce_challenge(verifier) == query["code_challenge"]


def _attributes(cookie: str) -> dict[str, str]:
    parts = [part.strip() for part in cookie.split(";")[1:]]
    return {part.split("=", 1)[0].lower(): part.split("=", 1)[1] if "=" in part else "" for part in parts}


@pytest.mark.parametrize("via", ["sign-in", "refresh"])
def test_token_cookie_attributes(hosted, providers, clock, via):
    resp = sign_in(hosted, providers)
    if via == "refresh":
        clock.advance(60)
        resp = refresh(hosted)
    access, refresh_cookie = _attributes(set_cookie(resp, ACCESS)), _attributes(set_cookie(resp, REFRESH))
    for attributes in (access, refresh_cookie):
        assert {"secure", "httponly"} <= set(attributes) and attributes["path"] == "/"
        assert "domain" not in attributes
    assert access["samesite"].lower() == "lax" and access["max-age"] == "900"
    assert refresh_cookie["samesite"].lower() == "strict"
    expected = 30 * DAY - (60 if via == "refresh" else 0)  # up to the family's absolute end
    assert refresh_cookie["max-age"] == str(expected)


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
    assert ACCESS not in resp.headers.get("set-cookie", "") and REFRESH not in resp.headers.get("set-cookie", "")
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
    assert first.headers["location"] == "/app?welcome=created"
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
    assert resp.headers["location"] == "/app?welcome=created"
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
    assert resp.headers["location"] == "/app?welcome=created"


def test_relative_next_is_kept():
    assert safe_next("/app/webcheck?tab=1") == "/app/webcheck?tab=1"


# Log in and Sign up intents


def test_sign_up_records_terms_acceptance_for_a_new_account(hosted, providers, clock, hosted_env):
    resp = sign_in(hosted, providers, next="/app/mail", intent="signup")
    assert resp.headers["location"] == "/app/mail"  # agreed to the terms already: no welcome note
    assert db_rows(hosted_env, "SELECT terms_accepted_at FROM users") == [(int(clock.now),)]


def test_log_in_creating_an_account_adds_the_one_time_welcome(hosted, providers, hosted_env):
    resp = sign_in(hosted, providers, next="/app/webcheck?tab=1")
    assert resp.headers["location"] == "/app/webcheck?tab=1&welcome=created"
    assert db_rows(hosted_env, "SELECT terms_accepted_at FROM users") == [(None,)]
    assert sign_in(hosted, providers).headers["location"] == "/app"  # only once: the account exists now


@pytest.mark.parametrize("intent", ["signup", "login", "admin"])
def test_an_existing_account_just_signs_in(hosted, providers, hosted_env, intent):
    sign_in(hosted, providers)
    resp = sign_in(hosted, providers, intent=intent)
    assert resp.headers["location"] == "/app"
    assert db_rows(hosted_env, "SELECT COUNT(*), MAX(terms_accepted_at) FROM users") == [(1, None)]


# Refresh families


def test_refresh_token_is_stored_only_as_a_keyed_hash(hosted, providers, hosted_env):
    raw = cookie_value(sign_in(hosted, providers), REFRESH)
    sid = db_rows(hosted_env, "SELECT id FROM sessions")[0][0]
    hosted.app.state.auth.store.close()  # flush the WAL into the main file
    db_path = Path(hosted_env["KESTRIX_DB"])
    data = b"".join(p.read_bytes() for p in db_path.parent.iterdir())
    assert raw.encode() not in data
    assert hashlib.sha256(raw.encode()).hexdigest().encode() not in data  # keyed, not a bare hash
    assert hosted.app.state.auth.csrf_token(sid).encode() not in data  # derived, never stored


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_database_file_and_directory_are_private(hosted, hosted_env):
    db_path = Path(hosted_env["KESTRIX_DB"])
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700


def test_refresh_rotates_both_tokens_and_keeps_the_family(hosted, providers, clock, hosted_env):
    first = sign_in(hosted, providers)
    headers = csrf(hosted)
    clock.advance(600)
    second = refresh(hosted, headers)
    assert second.status_code == 200
    assert second.json() == {"access_expires_at": int(clock.now) + 900}
    assert second.headers["cache-control"] == "no-store"
    assert cookie_value(second, REFRESH) != cookie_value(first, REFRESH)
    assert cookie_value(second, ACCESS) != cookie_value(first, ACCESS)
    assert csrf(hosted) == headers  # same family, same CSRF token
    assert db_rows(hosted_env, "SELECT COUNT(*), MAX(last_used_at) FROM sessions") == [(1, int(clock.now))]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM rotated_refresh_tokens") == [(1,)]


def test_reusing_a_rotated_refresh_token_revokes_the_family(hosted, providers, clock, hosted_env, caplog):
    stolen = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    assert refresh(hosted, headers).status_code == 200  # the user's browser rotates it
    clock.advance(11)  # past the refresh grace window (see test_hosted_refresh_grace.py)
    attacker = TestClient(hosted.app, base_url=str(hosted.base_url))
    attacker.cookies.set(REFRESH, stolen, domain="kestrix.example")
    reused = refresh(attacker, headers)
    assert reused.status_code == 401 and reused.json()["reason"] == "sign_in_required"
    assert db_rows(hosted_env, "SELECT revoked_at FROM sessions") == [(int(clock.now),)]
    assert "refresh token reuse detected; family revoked user=" in caplog.text
    # The whole family is gone at once: the user's current access and refresh tokens no longer work.
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}
    assert refresh(hosted, headers).status_code == 401


def test_refresh_needs_the_csrf_token_of_its_family(hosted, providers):
    sign_in(hosted, providers)
    assert hosted.post("/api/auth/refresh").status_code == 403
    wrong = hosted.post("/api/auth/refresh", headers={"x-csrf-token": "x" * 43})
    assert wrong.status_code == 403 and wrong.json()["reason"] == "csrf_failed"
    assert refresh(hosted).status_code == 200  # nothing was rotated by the refused attempts


def test_refresh_without_a_refresh_cookie_is_401_and_clears_cookies(hosted):
    resp = hosted.post("/api/auth/refresh", headers={"x-csrf-token": "x"})
    assert resp.status_code == 401 and resp.json()["reason"] == "sign_in_required"
    assert 'kx_rt=""' in resp.headers["set-cookie"]


def test_refresh_is_rate_limited_per_ip(hosted):
    for _ in range(60):
        assert hosted.post("/api/auth/refresh").status_code == 401
    limited = hosted.post("/api/auth/refresh")
    assert limited.status_code == 429 and limited.json()["reason"] == "rate_limited"
    assert int(limited.headers["retry-after"]) > 0


def test_me_offers_a_refresh_when_the_access_token_is_gone(hosted, providers, clock):
    sign_in(hosted, providers)
    signed_in = hosted.get("/api/auth/me").json()
    hosted.cookies.delete(ACCESS, domain="kestrix.example")  # the browser drops it after Max-Age
    assert hosted.get("/api/auth/me").json() == {
        "signed_in": False,
        "refreshable": True,
        "csrf_token": signed_in["csrf_token"],
    }
    clock.advance(30 * DAY)
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}


def test_idle_expiry(hosted, providers, clock):
    sign_in(hosted, providers)
    clock.advance(7 * DAY - 60)
    assert refresh(hosted).status_code == 200  # still within 7 days of the last refresh
    clock.advance(7 * DAY - 60)
    assert refresh(hosted).status_code == 200
    headers = csrf(hosted)
    clock.advance(7 * DAY)
    assert refresh(hosted, headers).status_code == 401
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}


def test_absolute_expiry_despite_activity(hosted, providers, clock):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    for _ in range(4):
        clock.advance(6 * DAY)
        assert refresh(hosted, headers).status_code == 200
    clock.advance(6 * DAY + 1)  # day 30
    assert refresh(hosted, headers).status_code == 401


def test_signing_in_again_starts_a_new_family(hosted, providers, hosted_env):
    first = cookie_value(sign_in(hosted, providers), REFRESH)
    second = cookie_value(sign_in(hosted, providers), REFRESH)
    assert first != second
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL") == [(1,)]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM users") == [(1,)]


# CSRF, logout and account deletion


def test_state_changing_requests_need_the_csrf_header(hosted, providers):
    sign_in(hosted, providers)
    url = {"url": "http://paypa1-login.example.top/verify"}
    assert hosted.post("/api/forensics/url", json=url).json()["reason"] == "csrf_failed"
    wrong = hosted.post("/api/forensics/url", json=url, headers={"x-csrf-token": "x" * 43})
    assert wrong.status_code == 403 and wrong.json()["reason"] == "csrf_failed"
    assert hosted.post("/api/forensics/url", json=url, headers=csrf(hosted)).status_code == 200


def test_csrf_token_from_another_family_is_refused(hosted, providers):
    sign_in(hosted, providers)
    old_token = csrf(hosted)
    sign_in(hosted, providers)
    resp = hosted.post("/api/forensics/url", json={"url": "https://a.example"}, headers=old_token)
    assert resp.status_code == 403


def test_logout_needs_csrf_and_revokes_the_family_at_once(hosted, providers, hosted_env):
    access = cookie_value(sign_in(hosted, providers), ACCESS)
    headers = csrf(hosted)
    assert hosted.post("/api/auth/logout").status_code == 403
    resp = hosted.post("/api/auth/logout", headers=headers)
    assert resp.status_code == 204
    cleared = " ".join(resp.headers.get_list("set-cookie")).lower()
    assert 'kx_at=""' in cleared and 'kx_rt=""' in cleared and cleared.count("max-age=0") == 2
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL") == [(1,)]
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}
    # The access token is still unexpired, but its family is revoked: refused immediately.
    hosted.cookies.set(ACCESS, access, domain="kestrix.example")
    assert hosted.get("/api/auth/me").json() == {"signed_in": False}
    assert hosted.post("/api/forensics/url", json={"url": "https://a.example"}, headers=headers).status_code == 401


def test_logout_with_an_expired_access_token_uses_the_refresh_family(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    clock.advance(1000)
    assert hosted.post("/api/auth/logout").status_code == 403
    assert hosted.post("/api/auth/logout", headers=headers).status_code == 204
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL") == [(1,)]


def test_logout_without_a_session_is_harmless(hosted):
    assert hosted.post("/api/auth/logout").status_code == 204


def test_account_deletion_needs_csrf_and_removes_user_and_all_families(hosted, providers, hosted_env):
    other_device = TestClient(hosted.app, base_url=str(hosted.base_url))
    sign_in(other_device, providers)
    assert other_device.get("/api/auth/me").json()["signed_in"]  # its family is now in the cache
    sign_in(hosted, providers)
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(2,)]
    assert hosted.delete("/api/auth/account").status_code == 403
    assert hosted.delete("/api/auth/account", headers=csrf(hosted)).status_code == 204
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM users") == [(0,)]
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM sessions") == [(0,)]
    assert other_device.get("/api/auth/me").json() == {"signed_in": False}
    assert other_device.post("/api/auth/refresh", headers={"x-csrf-token": "x"}).status_code == 401


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
