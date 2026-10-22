# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Idempotent refresh rotation (ADR 0007, amendment 1): a rotated refresh token answered within
``REFRESH_GRACE_S`` with the same successor, and every other reuse still revoking the family."""

import logging
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from kestrix.server.auth import REFRESH_GRACE_S

from .hosted_support import ACCESS, ORIGIN, REFRESH, cookie_value, csrf, refresh, sign_in


def db_rows(env, sql, *args):
    with sqlite3.connect(env["KESTRIX_DB"]) as db:
        return db.execute(sql, args).fetchall()


def client_with(hosted, token, user_agent=None):
    """Another browser context (a second tab, or a thief) holding this refresh token."""
    headers = {"user-agent": user_agent} if user_agent else None
    other = TestClient(hosted.app, base_url=ORIGIN, headers=headers)
    other.cookies.set(REFRESH, token, domain="kestrix.example")
    return other


def revoked(env):
    return db_rows(env, "SELECT revoked_at IS NOT NULL FROM sessions") == [(1,)]


def test_two_tabs_refreshing_at_the_same_instant_both_succeed_with_one_successor(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    tab_b = client_with(hosted, token0)
    first, second = refresh(hosted, headers), refresh(tab_b, headers)
    assert first.status_code == second.status_code == 200
    assert cookie_value(first, REFRESH) == cookie_value(second, REFRESH) != token0  # the same successor
    assert cookie_value(first, ACCESS) != cookie_value(second, ACCESS)  # each answer has its own access token
    assert not revoked(hosted_env)
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM rotated_refresh_tokens") == [(1,)]  # one rotation happened
    assert tab_b.get("/api/auth/me").json()["signed_in"] and hosted.get("/api/auth/me").json()["signed_in"]
    # The shared successor keeps working and rotates normally.
    assert refresh(tab_b, headers).status_code == 200
    assert db_rows(hosted_env, "SELECT COUNT(*) FROM rotated_refresh_tokens") == [(2,)]


def test_a_request_that_loses_the_rotation_race_gets_the_winners_successor(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    tab_b = client_with(hosted, token0)
    store = hosted.app.state.auth.store
    real, calls, winner = store.find_refresh, [], []

    def find_then_lose_the_race(refresh_hash):
        calls.append(refresh_hash)
        found = real(refresh_hash)
        if len(calls) == 1:  # this request has read the current token; the other tab now rotates it
            winner.append(refresh(tab_b, headers))
        return found

    store.find_refresh = find_then_lose_the_race
    try:
        loser = refresh(hosted, headers)
    finally:
        store.find_refresh = real
    assert loser.status_code == winner[0].status_code == 200
    assert cookie_value(loser, REFRESH) == cookie_value(winner[0], REFRESH)
    assert not revoked(hosted_env) and len(calls) == 3  # the lookup, the winner's lookup, the second look


def test_a_replay_exactly_at_the_end_of_the_window_is_still_a_duplicate(hosted, providers, clock, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    first = refresh(hosted, headers)
    clock.advance(REFRESH_GRACE_S)
    replay = refresh(client_with(hosted, token0), headers)
    assert replay.status_code == 200 and cookie_value(replay, REFRESH) == cookie_value(first, REFRESH)
    assert not revoked(hosted_env)


def test_a_replay_after_the_window_revokes_the_family(hosted, providers, clock, hosted_env, caplog):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    successor = cookie_value(refresh(hosted, headers), REFRESH)
    clock.advance(REFRESH_GRACE_S + 1)
    replay = refresh(client_with(hosted, token0), headers)
    assert replay.status_code == 401 and replay.json()["reason"] == "sign_in_required"
    assert revoked(hosted_env)
    assert "refresh token reuse detected; family revoked user=" in caplog.text
    assert refresh(client_with(hosted, successor), headers).status_code == 401  # the whole family is gone


def test_replaying_an_older_generation_revokes_even_inside_the_window(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    assert refresh(hosted, headers).status_code == 200  # token0 -> token1
    assert refresh(hosted, headers).status_code == 200  # token1 -> token2, so token1's successor is used
    replay = refresh(client_with(hosted, token0), headers)
    assert replay.status_code == 401
    assert revoked(hosted_env)


def test_replaying_a_token_whose_successor_was_used_revokes_inside_the_window(hosted, providers, clock, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    token1 = cookie_value(refresh(hosted, headers), REFRESH)  # token0 -> token1
    clock.advance(2)
    token2 = cookie_value(refresh(hosted, headers), REFRESH)  # token1 -> token2
    clock.advance(2)
    # token2 was rotated 2 s ago and its successor is unused: a duplicate, answered with the same successor
    current = cookie_value(refresh(hosted, headers), REFRESH)  # token2 -> token3
    assert refresh(client_with(hosted, token2), headers).status_code == 200
    # token1 was rotated 4 s ago, inside the window, but its successor (token2) has been used
    assert refresh(client_with(hosted, token1), headers).status_code == 401
    assert revoked(hosted_env)
    assert current != token2


def test_a_replay_from_another_client_fingerprint_revokes(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    assert refresh(hosted, headers).status_code == 200
    thief = client_with(hosted, token0, user_agent="Mozilla/5.0 (thief)")
    assert refresh(thief, headers).status_code == 401
    assert revoked(hosted_env)


def test_a_replay_in_the_window_still_needs_the_csrf_token_and_does_not_revoke(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    successor = cookie_value(refresh(hosted, headers), REFRESH)
    tab_b = client_with(hosted, token0)
    assert tab_b.post("/api/auth/refresh").status_code == 403
    assert tab_b.post("/api/auth/refresh", headers={"x-csrf-token": "x" * 43}).status_code == 403
    assert not revoked(hosted_env)
    assert cookie_value(refresh(tab_b, headers), REFRESH) == successor


def test_a_replay_after_logout_is_refused(hosted, providers, hosted_env):
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    assert refresh(hosted, headers).status_code == 200
    assert hosted.post("/api/auth/logout", headers=headers).status_code == 204
    assert refresh(client_with(hosted, token0), headers).status_code == 401


def test_the_grace_window_stores_and_logs_no_raw_token(hosted, providers, hosted_env, caplog):
    caplog.set_level(logging.DEBUG, logger="kestrix")
    token0 = cookie_value(sign_in(hosted, providers), REFRESH)
    headers = csrf(hosted)
    successor = cookie_value(refresh(hosted, headers), REFRESH)
    assert cookie_value(refresh(client_with(hosted, token0), headers), REFRESH) == successor
    assert "same successor returned user=" in caplog.text
    hosted.app.state.auth.store.close()  # flush the WAL into the main file
    data = b"".join(path.read_bytes() for path in sorted(Path(hosted_env["KESTRIX_DB"]).parent.iterdir()))
    for raw in (token0, successor):
        assert raw.encode() not in data
        assert raw not in caplog.text
    sealed = db_rows(hosted_env, "SELECT successor FROM rotated_refresh_tokens")[0][0]
    assert successor not in sealed and len(sealed) == 64  # 32 sealed bytes in hex, useless without token0
