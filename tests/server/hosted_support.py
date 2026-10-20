# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode test helpers: a fake clock and fake Google / GitHub endpoints.

The providers are an ``httpx.MockTransport``; no test touches the network.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi.testclient import TestClient

ORIGIN = "https://kestrix.example"
PEPPER = "pepper-" + "q" * 40
GOOGLE_ID, GOOGLE_SECRET = "google-client-id.apps.example", "google-client-secret-value"
GITHUB_ID, GITHUB_SECRET = "github-client-id", "github-client-secret-value"
GOOGLE_EMAIL, GITHUB_EMAIL = "ada@mail.example", "octo@mail.example"
GOOGLE_ACCESS, GITHUB_ACCESS = "ya29.google-access-token-value", "gho_github-access-token-value"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unsigned_jwt(claims: dict[str, Any]) -> str:
    header = b64(b'{"alg":"RS256","typ":"JWT"}')
    return f"{header}.{b64(json.dumps(claims).encode())}.{b64(b'signature')}"


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeProviders:
    clock: Clock
    requests: list[httpx.Request] = field(default_factory=list)
    nonce: str = ""
    google_overrides: dict[str, Any] = field(default_factory=dict)
    token_status: int = 200
    github_emails: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"email": "old@mail.example", "primary": False, "verified": True},
            {"email": GITHUB_EMAIL, "primary": True, "verified": True},
        ]
    )

    def google_claims(self) -> dict[str, Any]:
        now = int(self.clock.now)
        claims = {
            "iss": "https://accounts.google.com",
            "aud": GOOGLE_ID,
            "azp": GOOGLE_ID,
            "sub": "1099",
            "email": GOOGLE_EMAIL,
            "email_verified": True,
            "name": "Ada Lovelace",
            "iat": now,
            "exp": now + 3600,
            "nonce": self.nonce,
        }
        claims.update(self.google_overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url).split("?")[0]
        if url == "https://oauth2.googleapis.com/token":
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(
                200, json={"access_token": GOOGLE_ACCESS, "id_token": unsigned_jwt(self.google_claims())}
            )
        if url == "https://github.com/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": GITHUB_ACCESS, "token_type": "bearer"})
        if url == "https://api.github.com/user":
            return httpx.Response(200, json={"id": 4242, "login": "octo", "name": "Octo Cat"})
        if url == "https://api.github.com/user/emails":
            return httpx.Response(200, json=self.github_emails)
        return httpx.Response(404)

    def form(self, index: int = 0) -> dict[str, str]:
        token_requests = [r for r in self.requests if r.method == "POST"]
        return {k: v[0] for k, v in parse_qs(token_requests[index].content.decode()).items()}


def start_login(client: TestClient, provider: str = "google", **params: str) -> dict[str, str]:
    resp = client.get(f"/api/auth/login/{provider}", params=params, follow_redirects=False)
    assert resp.status_code == 302
    return {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}


def sign_in(client: TestClient, providers: FakeProviders, provider: str = "google", **params: str) -> httpx.Response:
    """Run the whole sign-in flow and return the callback response (not followed)."""
    query = start_login(client, provider, **params)
    providers.nonce = query.get("nonce", "")
    return client.get(
        f"/api/auth/callback/{provider}", params={"code": "auth-code", "state": query["state"]}, follow_redirects=False
    )


def csrf(client: TestClient) -> dict[str, str]:
    me = client.get("/api/auth/me").json()
    assert me["signed_in"]
    return {"x-csrf-token": me["csrf_token"]}
