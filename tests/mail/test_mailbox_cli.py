# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix mail connect|disconnect|status`` and the one-shot loopback listener."""

import threading
import urllib.request
from urllib.error import HTTPError

import pytest
from mailbox_support import (
    GOOD_CODE,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    MS_CLIENT_ID,
    authorization_params,
    configure,
)
from typer.testing import CliRunner

from kestrix.core.errors import Reason, Rejected
from kestrix.mail import cli
from kestrix.mail.mailbox import store
from kestrix.mail.mailbox.loopback import connect_with_loopback

runner = CliRunner()


def browser(fake_mail, query: str | None = None, path: str = "/mail/connect"):
    """A stand-in for the user's browser: it follows the authorize URL to the redirect."""

    def show(text: str) -> None:
        if not text.startswith("Opening"):
            return
        url = text.split("\n", 1)[1]
        params = authorization_params(url)
        fake_mail.challenge = params["code_challenge"]
        target = f"{params['redirect_uri'].replace('localhost', '127.0.0.1')}"
        target = target.rsplit("/mail/connect", 1)[0] + path
        suffix = query if query is not None else f"?code={GOOD_CODE}&state={params['state']}"
        threading.Thread(target=lambda: urllib.request.urlopen(target + suffix, timeout=5).read()).start()

    return show


def test_loopback_flow_connects_gmail(service, fake_mail) -> None:
    configure(service, "gmail")
    status = connect_with_loopback(service, "gmail", browser(fake_mail), open_browser=False, timeout_s=10)
    assert status.connected and store.refresh_token("gmail")
    redirect = fake_mail.token_forms[0]["redirect_uri"]
    assert redirect.startswith("http://127.0.0.1:") and redirect.endswith("/mail/connect")


def test_loopback_flow_uses_localhost_for_outlook(service, fake_mail) -> None:
    configure(service, "outlook")
    status = connect_with_loopback(service, "outlook", browser(fake_mail), open_browser=False, timeout_s=10)
    assert status.connected
    assert fake_mail.token_forms[0]["redirect_uri"].startswith("http://localhost:")


def test_loopback_refuses_a_forged_state(service, fake_mail) -> None:
    configure(service, "gmail")
    with pytest.raises(Rejected) as raised:
        connect_with_loopback(
            service, "gmail", browser(fake_mail, f"?code={GOOD_CODE}&state=forged"), open_browser=False, timeout_s=10
        )
    assert raised.value.reason is Reason.INVALID_INPUT and fake_mail.token_forms == []


def test_loopback_refusal_by_the_user_connects_nothing(service, fake_mail) -> None:
    configure(service, "gmail")
    with pytest.raises(Rejected, match="refused or cancelled"):
        connect_with_loopback(
            service, "gmail", browser(fake_mail, "?error=access_denied&state=x"), open_browser=False, timeout_s=10
        )
    assert store.refresh_token("gmail") is None


def test_loopback_answers_only_the_callback_path_and_times_out(service) -> None:
    configure(service, "gmail")
    codes: list[int] = []

    def probe(url: str) -> None:
        try:
            urllib.request.urlopen(url, timeout=5)
        except HTTPError as exc:
            codes.append(exc.code)

    def show(text: str) -> None:
        if text.startswith("Opening"):
            redirect = authorization_params(text.split("\n", 1)[1])["redirect_uri"]
            threading.Thread(target=probe, args=(redirect.rsplit("/mail/connect", 1)[0] + "/other",)).start()

    with pytest.raises(Rejected, match="no sign-in arrived"):
        connect_with_loopback(service, "gmail", show, open_browser=False, timeout_s=2)
    assert codes == [404]


def test_cli_connect_saves_settings_then_runs_the_flow(monkeypatch: pytest.MonkeyPatch, service, fake_mail) -> None:
    monkeypatch.setattr(cli, "MailboxService", lambda: service)
    real = cli.connect_with_loopback
    monkeypatch.setattr(
        cli,
        "connect_with_loopback",
        lambda svc, provider, show, **kw: real(
            svc, provider, lambda t: (show(t), browser(fake_mail)(t))[1], timeout_s=10, **kw
        ),
    )
    result = runner.invoke(
        cli.app,
        ["connect", "gmail", "--client-id", GOOGLE_CLIENT_ID, "--client-secret", GOOGLE_CLIENT_SECRET, "--no-browser"],
    )
    assert result.exit_code == 0, result.output
    assert "contacts Google or Microsoft" in result.output and "Connected Gmail as ada@gmail.example" in result.output
    assert GOOGLE_CLIENT_SECRET not in result.output
    status = runner.invoke(cli.app, ["status"])
    assert "gmail: connected as ada@gmail.example" in status.output and "outlook: not configured" in status.output


def test_cli_connect_rejects_a_bad_client_id(monkeypatch: pytest.MonkeyPatch, service) -> None:
    monkeypatch.setattr(cli, "MailboxService", lambda: service)
    result = runner.invoke(cli.app, ["connect", "outlook", "--client-id", "nope"])
    assert result.exit_code == 2 and "invalid_input" in result.output


def test_cli_disconnect_revokes_and_deletes(monkeypatch: pytest.MonkeyPatch, service, fake_mail) -> None:
    from mailbox_support import connect

    monkeypatch.setattr(cli, "MailboxService", lambda: service)
    connect(service, fake_mail, "gmail")
    result = runner.invoke(cli.app, ["disconnect", "gmail", "--forget-app"])
    assert result.exit_code == 0 and "Google confirmed" in result.output
    assert store.refresh_token("gmail") is None and store.load_app("gmail") is None
    outlook = runner.invoke(cli.app, ["disconnect", "outlook"])
    assert "myapps.microsoft.com" in outlook.output


def test_mail_group_lists_the_new_commands() -> None:
    from kestrix.cli import app as root_app

    out = runner.invoke(root_app, ["mail", "--help"]).output
    assert all(name in out for name in ("analyze", "connect", "disconnect", "status"))
    assert MS_CLIENT_ID not in out
