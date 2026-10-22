# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Deleting an account needs a recent sign-in (403 ``reauth_required``), on top of the CSRF token."""

import sqlite3

from .hosted_support import csrf, refresh, sign_in

WINDOW_S = 10 * 60


def count(env, table):
    with sqlite3.connect(env["KESTRIX_DB"]) as db:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_a_fresh_sign_in_can_delete_the_account(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    clock.advance(WINDOW_S)  # the last second of the window still counts
    assert hosted.delete("/api/auth/account", headers=csrf(hosted)).status_code == 204
    assert count(hosted_env, "users") == 0


def test_an_older_sign_in_must_sign_in_again_and_nothing_is_deleted(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    assert hosted.post("/api/forensics/url", json={"url": "https://a.example"}, headers=headers).status_code == 200
    clock.advance(WINDOW_S + 1)  # the 15-minute access token is still valid: only the sign-in is stale
    resp = hosted.delete("/api/auth/account", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["reason"] == "reauth_required"
    assert "sign in again" in resp.json()["detail"] and "10 minutes" in resp.json()["detail"]
    assert resp.headers["cache-control"] == "no-store"
    assert count(hosted_env, "users") == 1 and count(hosted_env, "sessions") == 1
    assert len(hosted.get("/api/history").json()["items"]) == 1  # the stored reports are untouched
    assert hosted.get("/api/auth/me").json()["signed_in"]  # still signed in, just not recently
    sign_in(hosted, providers)  # signing in again makes a new family
    assert hosted.delete("/api/auth/account", headers=csrf(hosted)).status_code == 204
    assert count(hosted_env, "users") == 0 and count(hosted_env, "sessions") == 0


def test_refreshing_does_not_renew_the_sign_in(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    clock.advance(400)
    assert refresh(hosted, headers).status_code == 200
    clock.advance(400)  # 800 s after the sign-in, 400 s after the refresh
    resp = hosted.delete("/api/auth/account", headers=headers)
    assert resp.status_code == 403 and resp.json()["reason"] == "reauth_required"
    assert count(hosted_env, "users") == 1


def test_the_csrf_token_is_still_required_first(hosted, providers, clock):
    sign_in(hosted, providers)
    clock.advance(WINDOW_S + 1)
    resp = hosted.delete("/api/auth/account")
    assert resp.status_code == 403 and resp.json()["reason"] == "csrf_failed"


def test_the_window_is_a_setting(make_hosted, providers, clock, hosted_env):
    client = make_hosted(reauth_window_s=60)
    sign_in(client, providers)
    clock.advance(61)
    assert client.delete("/api/auth/account", headers=csrf(client)).json()["detail"].endswith("last 1 minute")
