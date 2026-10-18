# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import json
import os
import stat
import sys

import pytest
from fastapi.testclient import TestClient

from kestrix.core import config
from kestrix.core.netguard import _is_public
from kestrix.server.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app(extra_hosts=frozenset({"testserver"})))


def test_health_and_security_headers(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["modules"] == ["detect", "forensics", "webcheck", "bitcoin", "mail"]
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_foreign_host_is_refused_including_testserver_by_default():
    assert TestClient(create_app()).get("/api/health").status_code == 421  # TestClient sends Host: testserver
    client = TestClient(create_app(extra_hosts=frozenset({"testserver"})))
    assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 421
    assert client.get("/api/health", headers={"host": "localhost:8765"}).status_code == 200
    assert client.get("/api/health", headers={"host": "[::1]:8765"}).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [{"origin": "https://evil.example"}, {"sec-fetch-site": "cross-site"}, {"origin": "null"}],
)
def test_cross_site_state_changes_are_refused(client, headers):
    resp = client.post("/api/forensics/file", files={"file": ("a.txt", b"hello")}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["reason"] == "cross_site_request"
    assert client.post("/api/detect/cases/c00-healthy-control/run", headers=headers).status_code == 403


def test_same_origin_requests_are_allowed(client):
    headers = {"origin": "http://localhost:8765", "sec-fetch-site": "same-origin"}
    assert client.post("/api/forensics/url", json={"url": "https://example.org"}, headers=headers).status_code == 200
    assert client.get("/api/settings", headers={"origin": "https://evil.example"}).status_code == 200  # reads are inert


def test_oversized_bodies_are_refused_before_reading(client):
    resp = client.post("/api/webcheck", content=b"{}", headers={"content-length": str(2 * 1024 * 1024)})
    assert resp.status_code == 413


def test_streamed_bodies_without_content_length_are_capped(client):
    def chunks():
        for _ in range(3):
            yield b"x" * 1024 * 1024

    resp = client.post("/api/forensics/url", content=chunks(), headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert resp.json()["reason"] == "input_too_large"


def test_http_errors_use_the_standard_envelope(client):
    resp = client.delete("/api/health")
    assert resp.status_code == 405
    assert set(resp.json()) == {"reason", "detail"}


def test_spa_fallback_cannot_escape_static_dir(client):
    for path in ["/..%2f..%2fpyproject.toml", "/../../pyproject.toml", "/%2e%2e/%2e%2e/LICENSE"]:
        resp = client.get(path)
        assert "Apache License" not in resp.text
        assert "[project]" not in resp.text
    assert client.get("/api/nope").status_code == 404


def test_api_key_is_never_returned(client):
    key = "sk-ant-test-" + "x" * 30
    assert client.put("/api/settings/anthropic-key", json={"key": key}).status_code == 204
    body = client.get("/api/settings").text
    assert body == json.dumps({"anthropic_key_configured": True}, separators=(",", ":"))
    assert key not in client.get("/api/openapi.json").text
    assert client.put("/api/settings/anthropic-key", json={"key": None}).status_code == 204
    assert client.get("/api/settings").json() == {"anthropic_key_configured": False}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_secret_file_is_private_even_if_directory_was_loose():
    config.config_dir().mkdir(parents=True, mode=0o755)
    os.chmod(config.config_dir(), 0o755)
    config.set_secret("anthropic_api_key", "k" * 30)
    secrets = config.config_dir() / "secrets.json"
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.config_dir().stat().st_mode) == 0o700
    assert [p.name for p in config.config_dir().iterdir()] == ["secrets.json"]  # no temp files left


def test_malformed_secret_file_is_ignored():
    config.config_dir().mkdir(parents=True)
    (config.config_dir() / "secrets.json").write_text("[1, 2]")
    assert config.anthropic_key() is None


@pytest.mark.parametrize(
    "ip",
    ["::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "::ffff:10.0.0.1", "169.254.169.254", "fd00::1"],
)
def test_netguard_blocks_embedded_private_addresses(ip):
    assert not _is_public(ipaddress.ip_address(ip))


def test_netguard_allows_public_addresses():
    assert _is_public(ipaddress.ip_address("93.184.216.34"))
    assert _is_public(ipaddress.ip_address("2606:4700:4700::1111"))
