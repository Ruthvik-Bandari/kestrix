# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Sign-in, token storage, refresh and revoke of the mailbox connector, against fake providers."""

import json
import logging
import os
import stat

import pytest
from mailbox_support import (
    GMAIL_SCOPE,
    GOOD_CODE,
    GOOGLE_ACCOUNT,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH,
    MS_ACCOUNT,
    MS_CLIENT_ID,
    MS_REFRESH,
    SECRET_VALUES,
    authorization_params,
    configure,
    connect,
)

from kestrix.core import config
from kestrix.core.errors import Reason, Rejected
from kestrix.mail.mailbox import store
from kestrix.mail.mailbox.oauth import pkce_pair


def secrets_file() -> dict[str, str]:
    return json.loads((config.config_dir() / "secrets.json").read_text())


def test_pkce_pair_is_s256_of_a_long_verifier() -> None:
    import base64
    import hashlib

    verifier, challenge = pkce_pair()
    assert len(verifier) >= 43
    assert challenge == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert pkce_pair()[0] != verifier


def test_gmail_authorize_url_is_read_only_pkce_with_state(service) -> None:
    configure(service, "gmail")
    started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="b")
    assert started.authorize_url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    params = authorization_params(started.authorize_url)
    assert params["scope"] == GMAIL_SCOPE
    assert params["code_challenge_method"] == "S256" and params["response_type"] == "code"
    assert params["client_id"] == GOOGLE_CLIENT_ID
    assert params["redirect_uri"] == "http://127.0.0.1:8765/mail/connect"
    assert len(params["state"]) >= 43 and "client_secret" not in params
    assert "send" not in params["scope"] and "modify" not in params["scope"]


def test_outlook_authorize_url_asks_only_mail_read(service) -> None:
    configure(service, "outlook")
    started = service.start("outlook", "http://localhost:8765/mail/connect", acknowledged=True, binding="b")
    assert started.authorize_url.startswith("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")
    scopes = authorization_params(started.authorize_url)["scope"].split()
    assert set(scopes) == {"openid", "profile", "offline_access", "https://graph.microsoft.com/Mail.Read"}


def test_start_needs_the_network_acknowledgement_and_a_configured_app(service) -> None:
    with pytest.raises(Rejected) as unconfigured:
        service.start("gmail", "http://127.0.0.1:1/mail/connect", acknowledged=True, binding="b")
    assert unconfigured.value.reason is Reason.MAILBOX_NOT_CONFIGURED
    configure(service, "gmail")
    with pytest.raises(Rejected) as unacknowledged:
        service.start("gmail", "http://127.0.0.1:1/mail/connect", acknowledged=False, binding="b")
    assert unacknowledged.value.reason is Reason.INVALID_INPUT


def test_gmail_sign_in_stores_only_the_refresh_token_with_0600(service, fake_mail) -> None:
    status = connect(service, fake_mail, "gmail")
    assert status.connected and status.account == GOOGLE_ACCOUNT
    token_form = next(f for f in fake_mail.token_forms if f["grant_type"] == "authorization_code")
    assert token_form["client_secret"] == GOOGLE_CLIENT_SECRET and token_form["code"] == GOOD_CODE
    assert token_form["redirect_uri"] == "http://127.0.0.1:8765/mail/connect"
    stored = secrets_file()
    assert stored["mail_gmail_refresh_token"] == GOOGLE_REFRESH
    assert not any(key.endswith("access_token") for key in stored) and not any("ya29" in v for v in stored.values())
    path = config.config_dir() / "secrets.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_outlook_sign_in_uses_the_id_token_label_and_no_client_secret(service, fake_mail) -> None:
    status = connect(service, fake_mail, "outlook")
    assert status.connected and status.account == MS_ACCOUNT
    form = fake_mail.token_forms[0]
    assert "client_secret" not in form and form["client_id"] == MS_CLIENT_ID
    assert stat.S_IMODE((config.config_dir() / "secrets.json").stat().st_mode) == 0o600
    assert secrets_file()["mail_outlook_refresh_token"].startswith(MS_REFRESH)


def test_state_is_single_use_and_unknown_state_is_refused(service, fake_mail) -> None:
    configure(service, "gmail")
    started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="b")
    state = authorization_params(started.authorize_url)["state"]
    with pytest.raises(Rejected):
        service.complete("not-the-state", GOOD_CODE, "b")
    fake_mail.challenge = authorization_params(started.authorize_url)["code_challenge"]
    service.complete(state, GOOD_CODE, "b")
    with pytest.raises(Rejected) as reused:
        service.complete(state, GOOD_CODE, "b")
    assert reused.value.reason is Reason.INVALID_INPUT


def test_sign_in_from_another_browser_is_refused_and_exchanges_nothing(service, fake_mail) -> None:
    configure(service, "gmail")
    started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="mine")
    state = authorization_params(started.authorize_url)["state"]
    for wrong in (None, "someone-else"):
        with pytest.raises(Rejected, match="not started in this browser"):
            service.complete(state, GOOD_CODE, wrong)
        configure(service, "gmail")
        started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="mine")
        state = authorization_params(started.authorize_url)["state"]
    assert fake_mail.token_forms == []  # the code never went to the provider


def test_expired_sign_in_is_refused(fake_mail, public_dns) -> None:
    from kestrix.mail.mailbox import MailboxService

    now = [1000.0]
    service = MailboxService(fake_mail.transport(), clock=lambda: now[0])
    configure(service, "gmail")
    started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="b")
    now[0] += 601
    with pytest.raises(Rejected, match="unknown or expired"):
        service.complete(authorization_params(started.authorize_url)["state"], GOOD_CODE, "b")


def test_a_wrong_pkce_verifier_fails_at_the_provider(service, fake_mail) -> None:
    configure(service, "gmail")
    started = service.start("gmail", "http://127.0.0.1:8765/mail/connect", acknowledged=True, binding="b")
    fake_mail.challenge = "challenge-of-some-other-verifier"
    with pytest.raises(Rejected, match="expired or was already used"):
        service.complete(authorization_params(started.authorize_url)["state"], GOOD_CODE, "b")
    assert store.refresh_token("gmail") is None


def test_consent_without_the_mail_scope_is_refused(service, fake_mail) -> None:
    fake_mail.google_scope = "openid email"
    with pytest.raises(Rejected, match="read-only mail access was not granted"):
        connect(service, fake_mail, "gmail")
    assert store.refresh_token("gmail") is None


def test_access_token_is_cached_in_memory_and_refreshed_after_expiry(fake_mail, public_dns) -> None:
    from kestrix.mail.mailbox import MailboxService

    now = [1000.0]
    service = MailboxService(fake_mail.transport(), clock=lambda: now[0])
    connect(service, fake_mail, "gmail")
    service.search("gmail", "", "inbox", None, 5)
    service.search("gmail", "", "inbox", None, 5)
    assert [f["grant_type"] for f in fake_mail.token_forms] == ["authorization_code"]
    now[0] += 3600
    service.search("gmail", "", "inbox", None, 5)
    assert [f["grant_type"] for f in fake_mail.token_forms] == ["authorization_code", "refresh_token"]
    assert fake_mail.token_forms[1]["refresh_token"] == GOOGLE_REFRESH


def test_microsoft_refresh_token_rotation_is_stored(fake_mail, public_dns) -> None:
    from kestrix.mail.mailbox import MailboxService

    now = [1000.0]
    service = MailboxService(fake_mail.transport(), clock=lambda: now[0])
    connect(service, fake_mail, "outlook")
    first = store.refresh_token("outlook")
    now[0] += 4000
    service.search("outlook", "", "inbox", None, 5)
    second = store.refresh_token("outlook")
    assert first != second and second == fake_mail.ms_refresh


def test_a_revoked_refresh_token_asks_for_reconnect_and_is_deleted(fake_mail, public_dns) -> None:
    from kestrix.mail.mailbox import MailboxService

    now = [1000.0]
    service = MailboxService(fake_mail.transport(), clock=lambda: now[0])
    connect(service, fake_mail, "gmail")
    now[0] += 4000
    fake_mail.google_refresh_error = "invalid_grant"
    with pytest.raises(Rejected) as raised:
        service.search("gmail", "", "inbox", None, 5)
    assert raised.value.reason is Reason.MAILBOX_RECONNECT_REQUIRED
    assert store.refresh_token("gmail") is None and store.load_app("gmail") is not None


def test_not_connected_and_not_configured_are_explicit(service) -> None:
    with pytest.raises(Rejected) as unconfigured:
        service.search("gmail", "", "inbox", None, 5)
    assert unconfigured.value.reason is Reason.MAILBOX_NOT_CONFIGURED
    configure(service, "gmail")
    with pytest.raises(Rejected) as unconnected:
        service.search("gmail", "", "inbox", None, 5)
    assert unconnected.value.reason is Reason.MAILBOX_NOT_CONNECTED


def test_disconnect_gmail_revokes_then_deletes(service, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    result = service.disconnect("gmail")
    assert result.revoked is True and fake_mail.revoked == [GOOGLE_REFRESH]
    assert "mail_gmail_refresh_token" not in secrets_file() and "mail_gmail_account" not in secrets_file()
    assert secrets_file()["mail_gmail_client_id"] == GOOGLE_CLIENT_ID  # the app settings stay unless asked
    service.disconnect("gmail", forget_app=True)
    assert not [k for k in secrets_file() if k.startswith("mail_gmail")]


def test_disconnect_deletes_locally_even_when_revoke_fails(service, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    fake_mail.revoke_status = 400
    result = service.disconnect("gmail")
    assert result.revoked is False and "myaccount.google.com/permissions" in result.detail
    assert store.refresh_token("gmail") is None


def test_disconnect_outlook_deletes_and_explains_how_to_revoke_consent(service, fake_mail) -> None:
    connect(service, fake_mail, "outlook")
    fake_mail.requests.clear()
    result = service.disconnect("outlook")
    assert result.revoked is None and "myapps.microsoft.com" in result.detail
    assert fake_mail.requests == []  # nothing is sent to Microsoft
    assert store.refresh_token("outlook") is None


def test_app_settings_are_validated_and_locked_while_connected(service, fake_mail) -> None:
    with pytest.raises(Rejected):
        service.configure("gmail", "bad id with spaces", None, None)
    with pytest.raises(Rejected):
        service.configure("outlook", "not-a-guid-but-long-enough", None, None)
    with pytest.raises(Rejected, match="no client secret"):
        service.configure("outlook", MS_CLIENT_ID, "a-secret", None)
    with pytest.raises(Rejected):
        service.configure("outlook", MS_CLIENT_ID, None, "bad tenant!")
    connect(service, fake_mail, "gmail")
    with pytest.raises(Rejected, match="disconnect"):
        service.configure("gmail", GOOGLE_CLIENT_ID, None, None)


def test_status_never_returns_credentials(service, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    body = service.status().model_dump_json()
    for value in (GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH, GOOGLE_CLIENT_ID):
        assert value not in body
    gmail = next(p for p in service.status().providers if p.provider == "gmail")
    assert gmail.configured and gmail.connected and gmail.account == GOOGLE_ACCOUNT


def test_no_secret_reaches_the_logs(service, fake_mail, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    connect(service, fake_mail, "gmail")
    service.search("gmail", "invoice", "inbox", None, 5)
    service.check("gmail", "18c0ffee01")
    service.disconnect("gmail")
    text = "\n".join(record.getMessage() for record in caplog.records)
    for value in (*SECRET_VALUES, "invoice", "18c0ffee01", "Quarterly update", "alice@example.com"):
        assert value not in text
