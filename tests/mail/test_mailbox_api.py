# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The local-mode mailbox routes end to end: settings, sign-in, search, check, history and protections."""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from mail_samples import BODY_SENTINEL, message
from mailbox_support import (
    GOOD_CODE,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH,
    MS_CLIENT_ID,
    authorization_params,
)

from kestrix.core import config

BASE = "/api/mail/mailbox"


def configure_gmail(client: TestClient) -> None:
    response = client.put(
        f"{BASE}/gmail/config", json={"client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET}
    )
    assert response.status_code == 200


def sign_in(client: TestClient, fake_mail, provider: str = "gmail") -> None:
    started = client.post(f"{BASE}/{provider}/start", json={"acknowledge_network": True})
    assert started.status_code == 200, started.text
    params = authorization_params(started.json()["authorize_url"])
    fake_mail.challenge = params["code_challenge"]
    done = client.post(f"{BASE}/callback", json={"state": params["state"], "code": GOOD_CODE})
    assert done.status_code == 200, done.text


def test_status_lists_both_providers_without_secrets(mailbox_client: TestClient) -> None:
    configure_gmail(mailbox_client)
    body = mailbox_client.get(f"{BASE}/status").json()
    assert [p["provider"] for p in body["providers"]] == ["gmail", "outlook"]
    gmail, outlook = body["providers"]
    assert gmail["configured"] is True and gmail["connected"] is False
    assert outlook["configured"] is False and outlook["register_redirect_uri"] == "http://localhost/mail/connect"
    assert "contact" in body["notice"] and gmail["hosts"] == [
        "accounts.google.com",
        "oauth2.googleapis.com",
        "gmail.googleapis.com",
    ]
    assert GOOGLE_CLIENT_SECRET not in json.dumps(body) and GOOGLE_CLIENT_ID not in json.dumps(body)


def test_config_responses_and_validation_never_echo_values(mailbox_client: TestClient) -> None:
    response = mailbox_client.put(
        f"{BASE}/gmail/config", json={"client_id": "bad id", "client_secret": "s3cret-value-xyz"}
    )
    assert response.status_code == 400 and "s3cret-value-xyz" not in response.text and "bad id" not in response.text
    extra = mailbox_client.put(f"{BASE}/gmail/config", json={"client_id": GOOGLE_CLIENT_ID, "unknown": 1})
    assert extra.status_code == 422
    assert mailbox_client.put(f"{BASE}/yahoo/config", json={"client_id": GOOGLE_CLIENT_ID}).status_code == 422


def test_sign_in_search_check_and_disconnect(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    status = mailbox_client.get(f"{BASE}/status").json()["providers"][0]
    assert status["connected"] and status["account"] == "ada@gmail.example"
    found = mailbox_client.post(f"{BASE}/gmail/search", json={"query": "update", "folder": "inbox", "limit": 10})
    assert found.status_code == 200 and found.json()["messages"][0]["id"] == "18c0ffee01"
    fake_mail.gmail[0].raw = message(headers=[("Reply-To", "pay@other.example")])
    report = mailbox_client.post(f"{BASE}/gmail/check", json={"message_id": "18c0ffee01"})
    assert report.status_code == 200 and report.json()["verdict"] == "suspicious"
    assert BODY_SENTINEL not in report.text
    gone = mailbox_client.delete(f"{BASE}/gmail")
    assert gone.status_code == 200 and gone.json()["revoked"] is True
    assert GOOGLE_REFRESH in fake_mail.revoked
    assert mailbox_client.post(f"{BASE}/gmail/search", json={}).json()["reason"] == "mailbox_not_connected"


def test_start_sets_a_strict_httponly_cookie_scoped_to_the_routes(mailbox_client: TestClient) -> None:
    configure_gmail(mailbox_client)
    response = mailbox_client.post(f"{BASE}/gmail/start", json={"acknowledge_network": True})
    cookie = response.headers["set-cookie"].lower()
    assert "kx_mailbox_flow=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "path=/api/mail/mailbox" in cookie and "max-age=600" in cookie
    assert response.json()["authorize_url"].startswith("https://accounts.google.com/")


def test_callback_from_a_browser_that_did_not_start_it_is_refused(
    mailbox_client: TestClient, fake_mail, public_dns
) -> None:
    configure_gmail(mailbox_client)
    started = mailbox_client.post(f"{BASE}/gmail/start", json={"acknowledge_network": True}).json()
    params = authorization_params(started["authorize_url"])
    stranger = TestClient(mailbox_client.app, base_url="http://127.0.0.1:8765")  # no cookie
    response = stranger.post(f"{BASE}/callback", json={"state": params["state"], "code": GOOD_CODE})
    assert response.status_code == 400 and response.json()["reason"] == "invalid_input"
    assert fake_mail.token_forms == []
    retry = mailbox_client.post(f"{BASE}/callback", json={"state": params["state"], "code": GOOD_CODE})
    assert retry.status_code == 400  # the flow was consumed by the refused attempt


def test_a_cancelled_sign_in_connects_nothing(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    started = mailbox_client.post(f"{BASE}/gmail/start", json={"acknowledge_network": True}).json()
    state = authorization_params(started["authorize_url"])["state"]
    response = mailbox_client.post(f"{BASE}/callback", json={"state": state, "error": "access_denied", "code": None})
    assert response.status_code == 400 and "access_denied" in response.json()["detail"]
    assert mailbox_client.get(f"{BASE}/status").json()["providers"][0]["connected"] is False
    assert fake_mail.token_forms == []


def test_start_requires_the_network_acknowledgement(mailbox_client: TestClient) -> None:
    configure_gmail(mailbox_client)
    response = mailbox_client.post(f"{BASE}/gmail/start", json={})
    assert response.status_code == 400 and "acknowledge_network" in response.json()["detail"]


def test_outlook_needs_the_dashboard_opened_at_localhost(mailbox_client: TestClient, fake_mail) -> None:
    mailbox_client.put(f"{BASE}/outlook/config", json={"client_id": MS_CLIENT_ID})
    refused = mailbox_client.post(f"{BASE}/outlook/start", json={"acknowledge_network": True})
    assert refused.status_code == 400 and "http://localhost" in refused.json()["detail"]
    local = TestClient(mailbox_client.app, base_url="http://localhost:8765")
    started = local.post(f"{BASE}/outlook/start", json={"acknowledge_network": True})
    assert started.status_code == 200
    redirect = authorization_params(started.json()["authorize_url"])["redirect_uri"]
    assert redirect == "http://localhost:8765/mail/connect"
    sign_in(local, fake_mail, "outlook")
    assert local.get(f"{BASE}/status").json()["providers"][1]["account"] == "ada@contoso.example"


def test_gmail_redirect_uses_the_host_and_port_the_dashboard_was_opened_with(mailbox_client: TestClient) -> None:
    configure_gmail(mailbox_client)
    started = mailbox_client.post(f"{BASE}/gmail/start", json={"acknowledge_network": True}).json()
    assert authorization_params(started["authorize_url"])["redirect_uri"] == "http://127.0.0.1:8765/mail/connect"


def test_rate_limit_is_a_429_with_retry_after(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    fake_mail.rate_limit_path = "/gmail/v1"
    response = mailbox_client.post(f"{BASE}/gmail/search", json={})
    assert response.status_code == 429 and response.headers["retry-after"] == "17"
    assert response.json()["reason"] == "rate_limited"


def test_reason_codes_map_to_statuses(mailbox_client: TestClient, fake_mail) -> None:
    unconfigured = mailbox_client.post(f"{BASE}/gmail/search", json={})
    assert (unconfigured.status_code, unconfigured.json()["reason"]) == (409, "mailbox_not_configured")
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    fake_mail.valid_access.clear()
    fake_mail.google_refresh_error = "invalid_grant"
    revoked = mailbox_client.post(f"{BASE}/gmail/search", json={})
    assert (revoked.status_code, revoked.json()["reason"]) == (409, "mailbox_reconnect_required")
    fake_mail.google_refresh_error = None


def test_check_options_are_validated(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    bad = mailbox_client.post(
        f"{BASE}/gmail/check", json={"message_id": "18c0ffee01", "protected_domains": ["not a domain"]}
    )
    assert bad.status_code == 400
    too_many = mailbox_client.post(
        f"{BASE}/gmail/check", json={"message_id": "x", "protected_domains": ["a.example"] * 21}
    )
    assert too_many.status_code == 422


def test_cross_site_and_foreign_host_requests_are_refused(mailbox_client: TestClient) -> None:
    configure_gmail(mailbox_client)
    cross = mailbox_client.post(
        f"{BASE}/gmail/start", json={"acknowledge_network": True}, headers={"Origin": "https://evil.example"}
    )
    assert cross.status_code == 403
    site = mailbox_client.post(
        f"{BASE}/gmail/start", json={"acknowledge_network": True}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert site.status_code == 403
    foreign = TestClient(mailbox_client.app, base_url="http://rebind.example")
    assert foreign.get(f"{BASE}/status").status_code == 421


def test_a_check_is_recorded_in_history_without_subject_or_address(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    assert mailbox_client.post(f"{BASE}/gmail/check", json={"message_id": "18c0ffee01"}).status_code == 200
    listing = mailbox_client.get("/api/history").json()
    assert listing["total"] == 1 and listing["items"][0]["tool"] == "mail"
    assert set(listing["items"][0]) == {"id", "tool", "created_at", "verdict", "findings"}
    with sqlite3.connect(config.config_dir() / "history.sqlite3") as db:
        columns = db.execute("SELECT tool, verdict, findings, created_at FROM history").fetchall()
        everything = " ".join(str(v) for row in db.execute("SELECT id, tool, verdict FROM history") for v in row)
    assert columns[0][0] == "mail" and "Quarterly" not in everything and "alice@" not in everything


def test_searching_and_listing_are_not_recorded_or_stored(mailbox_client: TestClient, fake_mail) -> None:
    configure_gmail(mailbox_client)
    sign_in(mailbox_client, fake_mail)
    mailbox_client.post(f"{BASE}/gmail/search", json={"query": "update"})
    assert mailbox_client.get("/api/history").json()["total"] == 0
    for path in config.config_dir().rglob("*"):
        if path.is_file():
            assert b"Quarterly update" not in path.read_bytes() and b"alice@example.com" not in path.read_bytes()


def test_openapi_and_docs_describe_the_routes(mailbox_client: TestClient) -> None:
    paths = mailbox_client.get("/api/openapi.json").json()["paths"]
    assert f"{BASE}/status" in paths and f"{BASE}/{{provider}}/check" in paths


@pytest.mark.parametrize("path", ["/mail/connect", "/mail"])
def test_the_dashboard_serves_the_callback_page(mailbox_client: TestClient, path: str) -> None:
    assert mailbox_client.get(path).status_code in {200, 503}  # 503 only when the bundle is not built
