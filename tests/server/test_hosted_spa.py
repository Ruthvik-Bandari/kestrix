# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The dashboard's client-side routes are served as index.html in both modes (ADR 0004).

Hosted: the landing page at ``/``, the dashboard under ``/app``, and ``/welcome``, ``/signin``,
``/privacy`` and ``/terms``. Unknown ``/api/`` paths stay JSON errors, never the page.
"""

import pytest
from fastapi.testclient import TestClient

from kestrix.server import app as app_module
from kestrix.server.app import create_app

from .hosted_support import csrf, sign_in

INDEX = "<!doctype html><title>Kestrix test bundle</title>"
SPA_PATHS = [
    "/",
    "/app",
    "/app/mail",
    "/app/webcheck",
    "/welcome?signin=failed",
    "/signin?next=%2Fapp",
    "/privacy",
    "/terms",
]


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text(INDEX)
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setattr(app_module, "STATIC_DIR", tmp_path)
    return tmp_path


@pytest.mark.parametrize("path", SPA_PATHS)
def test_hosted_serves_the_page_for_client_routes(hosted, bundle, path):
    resp = hosted.get(path)
    assert resp.status_code == 200
    assert resp.text == INDEX
    assert resp.headers["strict-transport-security"].startswith("max-age=")


def test_hosted_serves_bundle_assets(hosted, bundle):
    resp = hosted.get("/assets/app.js")
    assert resp.status_code == 200
    assert resp.text == "console.log(1)"


def test_hosted_unknown_api_paths_stay_json(hosted, providers, bundle):
    signed_out = hosted.get("/api/nope")
    assert signed_out.status_code == 401
    assert signed_out.json()["reason"] == "sign_in_required"
    sign_in(hosted, providers)
    resp = hosted.get("/api/nope")
    assert resp.status_code == 404
    assert resp.json()["reason"] == "not_found"
    # Writes to unknown paths hit no route; the catch-all page route is GET-only.
    resp = hosted.post("/api/nope", headers=csrf(hosted))
    assert resp.status_code == 405
    assert resp.json()["reason"] == "method_not_allowed"
    assert hosted.get("/api/detect/cases").json()["reason"] == "not_found"


@pytest.mark.parametrize("path", ["/", "/welcome", "/mail", "/privacy", "/terms"])
def test_local_mode_is_unchanged(bundle, path):
    client = TestClient(create_app(extra_hosts=frozenset({"testserver"})))
    resp = client.get(path)
    assert resp.status_code == 200
    assert resp.text == INDEX
    assert "strict-transport-security" not in resp.headers
    nope = client.get("/api/nope")
    assert nope.status_code == 404
    assert nope.json()["reason"] == "not_found"
