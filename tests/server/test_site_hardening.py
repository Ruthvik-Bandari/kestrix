# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hardening of Kestrix's own site: headers and CSP, static caching, error bodies, CORS, audit logs."""

import logging
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from kestrix.server import app as app_module
from kestrix.server import headers as headers_module
from kestrix.server.app import create_app
from kestrix.server.settings import Settings, SettingsError, load_settings

from .hosted_support import ACCESS, ORIGIN, REFRESH, csrf, sign_in
from .test_hosted_settings import BASE

INDEX = "<!doctype html><title>bundle</title>"


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text(INDEX)
    (tmp_path / "favicon.svg").write_text("<svg/>")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app-abc123.js").write_text("console.log(1)")
    monkeypatch.setattr(app_module, "STATIC_DIR", tmp_path)
    return tmp_path


def directives(csp: str) -> dict[str, list[str]]:
    parsed = {}
    for part in csp.split(";"):
        name, *values = part.split()
        parsed[name] = values
    return parsed


def assert_site_headers(headers: httpx.Headers) -> None:
    csp = directives(headers["content-security-policy"])
    assert csp["script-src"] == ["'self'"]
    assert csp["style-src"] == ["'self'"]
    assert csp["object-src"] == ["'none'"] and csp["base-uri"] == ["'none'"]
    assert csp["frame-ancestors"] == ["'none'"] and csp["form-action"] == ["'self'"]
    assert csp["default-src"] == ["'self'"] and csp["frame-src"] == ["'none'"]
    assert not {"'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:"} & {v for vs in csp.values() for v in vs}
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    policy = headers["permissions-policy"]
    assert all(f"{feature}=()" in policy for feature in ("camera", "microphone", "geolocation", "payment", "usb"))
    assert "server" not in headers or "uvicorn" not in headers["server"].lower()


def test_every_hosted_response_kind_carries_the_headers(hosted, providers, bundle):
    sign_in(hosted, providers)
    responses = [
        hosted.get("/"),
        hosted.get("/assets/app-abc123.js"),
        hosted.get("/assets/missing.js"),
        hosted.get("/api/health"),
        hosted.get("/api/nope"),
        hosted.get("/api/detect/cases"),  # local-only module: 404
        hosted.get("/api/health", headers={"host": "attacker.example"}),  # 421
        hosted.post(
            "/api/forensics/url", json={"url": "https://a.example"}, headers={"origin": "https://evil.example"}
        ),
        hosted.post("/api/forensics/url", json={"url": 5}, headers=csrf(hosted)),  # 422
        hosted.get("/api/auth/login/google", follow_redirects=False),
    ]
    for response in responses:
        assert_site_headers(response.headers)
        assert "upgrade-insecure-requests" in response.headers["content-security-policy"]
        assert response.headers["strict-transport-security"].startswith("max-age=63072000; includeSubDomains")


def test_local_mode_has_the_same_csp_without_hsts_or_the_upgrade_directive(bundle):
    local = TestClient(create_app(extra_hosts=frozenset({"testserver"}), server_settings=Settings()))
    for path in ("/", "/api/health", "/assets/missing.js"):
        response = local.get(path)
        assert_site_headers(response.headers)
        assert "strict-transport-security" not in response.headers
        assert "upgrade-insecure-requests" not in response.headers["content-security-policy"]


def test_hsts_preload_is_the_owners_choice(hosted_env, monkeypatch, providers):
    default = load_settings(hosted_env).hosted
    assert default is not None and not default.hsts_preload
    assert headers_module.hosted_headers()["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains"
    chosen = load_settings({**hosted_env, "KESTRIX_HSTS_PRELOAD": "1"})
    assert chosen.hosted is not None and chosen.hosted.hsts_preload
    assert headers_module.hosted_headers(hsts_preload=True)["Strict-Transport-Security"].endswith("; preload")
    app = create_app(server_settings=chosen, provider_transport=httpx.MockTransport(providers.handler))
    client = TestClient(app, base_url=ORIGIN)
    assert client.get("/api/health").headers["strict-transport-security"].endswith("includeSubDomains; preload")
    with pytest.raises(SettingsError, match="KESTRIX_HSTS_PRELOAD"):
        load_settings({**BASE, "KESTRIX_HSTS_PRELOAD": "maybe", "KESTRIX_SESSION_PEPPER": "p" * 40})


def test_hashed_assets_are_immutable_and_the_page_is_revalidated(hosted, bundle):
    asset = hosted.get("/assets/app-abc123.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    for path in ("/", "/app", "/privacy", "/favicon.svg"):
        assert hosted.get(path).headers["cache-control"] == "no-cache", path
    assert hosted.get("/api/health").headers["cache-control"] == "no-store"


def test_a_missing_bundle_file_is_404_not_the_page(hosted, bundle):
    response = hosted.get("/assets/old-chunk-deadbeef.js")
    assert response.status_code == 404 and response.json()["reason"] == "not_found"
    assert "cache-control" not in response.headers or "immutable" not in response.headers["cache-control"]


@pytest.mark.parametrize(
    "path", ["/%00", "/assets/%00.js", "/" + "a" * 5000, "/..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/x"], ids=range(5)
)
def test_odd_paths_never_become_a_server_error_or_leave_the_bundle(hosted, bundle, path):
    response = hosted.get(path)
    assert response.status_code in {200, 404}
    assert "root:" not in response.text


def test_no_cors_headers_ever(hosted, providers, bundle):
    sign_in(hosted, providers)
    probes = [
        hosted.get("/api/health", headers={"origin": "https://evil.example"}),
        hosted.options(
            "/api/forensics/url",
            headers={"origin": "https://evil.example", "access-control-request-method": "POST"},
        ),
        hosted.options("/api/health", headers={"origin": ORIGIN, "access-control-request-method": "GET"}),
    ]
    for response in probes:
        assert not [name for name in response.headers if name.startswith("access-control-")]


def test_hosted_validation_errors_do_not_echo_the_rejected_values(hosted, providers):
    sign_in(hosted, providers)
    body = {"url": ["leak-me-1"], "scope": "page", "leak-key": "leak-me-2"}
    response = hosted.post("/api/webcheck", json=body, headers=csrf(hosted))
    assert response.status_code == 422
    assert "leak-me-1" not in response.text and "leak-me-2" not in response.text
    problems = response.json()["detail"]
    assert all(set(problem) == {"type", "loc", "msg"} for problem in problems)
    assert ["body", "url"] in [problem["loc"] for problem in problems]  # still tells the client which field


def test_hosted_malformed_json_is_422_without_the_body(hosted, providers):
    sign_in(hosted, providers)
    response = hosted.post(
        "/api/webcheck", content=b'{"url": "leak-me-3", ', headers={**csrf(hosted), "content-type": "application/json"}
    )
    assert response.status_code == 422 and "leak-me-3" not in response.text


def test_local_validation_errors_keep_fastapis_standard_body():
    local = TestClient(create_app(extra_hosts=frozenset({"testserver"}), server_settings=Settings()))
    response = local.post("/api/webcheck", json={"url": 5})
    assert response.status_code == 422 and response.json()["detail"][0]["input"] == 5


def test_hosted_cookies_are_host_bound_and_clear_on_logout(hosted, providers):
    response = sign_in(hosted, providers)
    cookies = {
        name: next(v for v in response.headers.get_list("set-cookie") if v.startswith(f"{name}=")).lower()
        for name in (ACCESS, REFRESH)
    }
    for name, header in cookies.items():
        assert name.startswith("__host-") or header.startswith("__host-")
        assert "secure" in header and "httponly" in header and "path=/" in header and "domain" not in header
        assert "samesite=" in header
    out = hosted.post("/api/auth/logout", headers=csrf(hosted))
    cleared = [v.lower() for v in out.headers.get_list("set-cookie")]
    assert len(cleared) == 2 and all("max-age=0" in v and "path=/" in v and "secure" in v for v in cleared)


def test_auth_events_are_audited_with_a_hashed_user_and_no_personal_data(hosted, providers, caplog):
    caplog.set_level(logging.INFO, logger="kestrix.auth")
    sign_in(hosted, providers)
    hosted.post("/api/auth/logout", headers=csrf(hosted))
    sign_in(hosted, providers)
    assert hosted.delete("/api/auth/account", headers=csrf(hosted)).status_code == 204
    lines = [r.getMessage() for r in caplog.records if r.name == "kestrix.auth"]
    assert re.search(r"^sign-in provider=google user=[0-9a-f]{16} new=True$", lines[0])
    assert re.search(r"^sign-out user=[0-9a-f]{16}$", lines[1])
    assert re.search(r"^sign-in provider=google user=[0-9a-f]{16} new=False$", lines[2])
    assert re.search(r"^account deleted user=[0-9a-f]{16}$", lines[3])
    assert lines[0].split("user=")[1][:16] == lines[1].split("user=")[1]
    text = caplog.text
    for secret in ("ada@mail.example", "Ada Lovelace", "1099"):
        assert secret not in text


def test_open_redirects_through_next_are_refused_end_to_end(hosted, providers):
    for target in ("//evil.example", "https://evil.example", "/\\evil.example", "/a\tb", "/a\nb"):
        location = sign_in(hosted, providers, next=target).headers["location"]
        assert location.startswith("/app") and "evil" not in location, target


def test_the_built_dashboard_has_no_inline_code():
    index = app_module.STATIC_DIR / "index.html"
    if not index.is_file():
        pytest.skip("the dashboard is not built (npm --prefix frontend run build)")
    page = index.read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", page), "inline <script>"
    assert "<style" not in page and not re.search(r"\sstyle=", page), "inline style"
    assert not re.search(r"\son[a-z]+\s*=", page), "inline event handler"
    assert "javascript:" not in page
    hashed = list((app_module.STATIC_DIR / "assets").glob("*-*.js"))
    assert hashed, "bundle files are content-hashed"
