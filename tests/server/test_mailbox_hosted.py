# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The mailbox connector is local-mode only (ADR 0009): the hosted service has no such routes."""

import pytest

from .hosted_support import csrf, sign_in

BASE = "/api/mail/mailbox"
ROUTES = [
    ("GET", f"{BASE}/status"),
    ("PUT", f"{BASE}/gmail/config"),
    ("POST", f"{BASE}/gmail/start"),
    ("POST", f"{BASE}/outlook/start"),
    ("POST", f"{BASE}/callback"),
    ("POST", f"{BASE}/gmail/search"),
    ("POST", f"{BASE}/outlook/check"),
    ("DELETE", f"{BASE}/gmail"),
]


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_hosted_service_answers_404_for_every_mailbox_route(hosted, providers, method, path):
    anonymous = hosted.request(method, path, json={})
    assert anonymous.status_code == 404 and anonymous.json()["reason"] == "not_found"
    sign_in(hosted, providers)
    signed_in = hosted.request(method, path, json={"acknowledge_network": True}, headers=csrf(hosted))
    assert signed_in.status_code == 404 and signed_in.json()["reason"] == "not_found"


def test_hosted_app_does_not_register_the_routes_or_describe_them(hosted):
    assert not [p for p in hosted.app.openapi()["paths"] if p.startswith(BASE)]
    assert "/api/mail/analyze" in hosted.app.openapi()["paths"]  # the upload check stays


def test_hosted_app_never_builds_a_mailbox_service(hosted, providers):
    sign_in(hosted, providers)
    assert not hasattr(hosted.app.state, "mailbox")
    assert hosted.get("/api/health").json()["modules"] == ["forensics", "webcheck", "mail"]
