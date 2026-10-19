# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted mode refuses to start unless it is fully and safely configured."""

import pytest
from typer.testing import CliRunner

from kestrix.cli import app as cli
from kestrix.core import config
from kestrix.server.app import create_app
from kestrix.server.settings import SettingsError, load_settings

from .hosted_support import GOOGLE_ID, GOOGLE_SECRET, ORIGIN, PEPPER

BASE = {
    "KESTRIX_MODE": "hosted",
    "KESTRIX_PUBLIC_ORIGIN": ORIGIN,
    "KESTRIX_SESSION_PEPPER": PEPPER,
    "KESTRIX_GOOGLE_CLIENT_ID": GOOGLE_ID,
    "KESTRIX_GOOGLE_CLIENT_SECRET": GOOGLE_SECRET,
}


def test_local_is_the_default_and_needs_nothing():
    assert load_settings({}).mode == "local"
    assert load_settings({"KESTRIX_MODE": "local"}).hosted is None


def test_a_complete_hosted_configuration_loads():
    hosted = load_settings(BASE).hosted
    assert hosted is not None
    assert (hosted.public_origin, hosted.public_host) == (ORIGIN, "kestrix.example")
    assert list(hosted.providers) == ["google"]
    assert hosted.db_path == config.config_dir() / "hosted.sqlite3"
    assert not hosted.trust_proxy_headers
    assert hosted.client_ip_header is None
    fly = load_settings({**BASE, "KESTRIX_CLIENT_IP_HEADER": "Fly-Client-IP"}).hosted
    assert fly is not None and fly.client_ip_header == "fly-client-ip"
    assert PEPPER not in repr(hosted) and GOOGLE_SECRET not in repr(hosted)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"KESTRIX_MODE": "public"}, "KESTRIX_MODE"),
        ({"KESTRIX_CLIENT_IP_HEADER": "Fly Client IP"}, "header name"),
        ({"KESTRIX_CLIENT_IP_HEADER": "Fly-Client-IP", "KESTRIX_TRUST_PROXY_HEADERS": "1"}, "not both"),
        ({"KESTRIX_PUBLIC_ORIGIN": ""}, "KESTRIX_PUBLIC_ORIGIN"),
        ({"KESTRIX_PUBLIC_ORIGIN": "http://kestrix.example"}, "https"),
        ({"KESTRIX_PUBLIC_ORIGIN": "https://kestrix.example/app"}, "only a scheme and host"),
        ({"KESTRIX_PUBLIC_ORIGIN": "https://user:pw@kestrix.example"}, "only a scheme and host"),
        ({"KESTRIX_SESSION_PEPPER": ""}, "KESTRIX_SESSION_PEPPER"),
        ({"KESTRIX_SESSION_PEPPER": "x" * 31}, "at least 32 bytes"),
        ({"KESTRIX_GOOGLE_CLIENT_SECRET": ""}, "set both"),
        ({"KESTRIX_GOOGLE_CLIENT_ID": "", "KESTRIX_GOOGLE_CLIENT_SECRET": ""}, "at least one sign-in provider"),
        ({"KESTRIX_TRUST_PROXY_HEADERS": "maybe"}, "KESTRIX_TRUST_PROXY_HEADERS"),
        ({"KESTRIX_ABUSE_CONTACT": "abuse@kestrix.example\r\nX-Evil: 1"}, "KESTRIX_ABUSE_CONTACT"),
        ({"KESTRIX_LOG_SALT": "short"}, "KESTRIX_LOG_SALT"),
    ],
)
def test_misconfiguration_is_refused(change, message):
    with pytest.raises(SettingsError, match=message):
        load_settings({**BASE, **change})


def test_origin_is_normalized():
    assert (
        load_settings({**BASE, "KESTRIX_PUBLIC_ORIGIN": "HTTPS://Kestrix.Example:443/"}).hosted.public_origin == ORIGIN
    )
    custom = load_settings({**BASE, "KESTRIX_PUBLIC_ORIGIN": "https://kestrix.example:8443"}).hosted
    assert (custom.public_origin, custom.public_host) == ("https://kestrix.example:8443", "kestrix.example")


def test_create_app_refuses_to_start_in_misconfigured_hosted_mode(monkeypatch):
    monkeypatch.setenv("KESTRIX_MODE", "hosted")
    monkeypatch.setenv("KESTRIX_PUBLIC_ORIGIN", "http://kestrix.example")
    with pytest.raises(SettingsError):
        create_app()


def test_serve_hosted_exits_with_a_clear_error_when_unconfigured():
    result = CliRunner().invoke(cli, ["serve-hosted"])
    assert result.exit_code == 2
    assert "KESTRIX_PUBLIC_ORIGIN" in result.output


def test_local_dashboard_refuses_hosted_mode(monkeypatch):
    for name, value in BASE.items():
        monkeypatch.setenv(name, value)
    result = CliRunner().invoke(cli, ["dashboard", "--no-open"])
    assert result.exit_code == 2
    assert "serve-hosted" in result.output
