# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Fake Google and Microsoft endpoints for the mailbox connector tests (``httpx.MockTransport``).

No test touches the network and no value here is a real credential or real mail.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit

import httpx
from mail_samples import message

GOOGLE_CLIENT_ID = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "GOCSPX-fake-client-secret-value"
MS_CLIENT_ID = "11111111-2222-3333-4444-555555555555"
GOOD_CODE = "good-authorization-code"
GOOGLE_REFRESH = "1//fake-google-refresh-token"
MS_REFRESH = "0.fake-microsoft-refresh-token-"
MS_ACCOUNT = "ada@contoso.example"
GOOGLE_ACCOUNT = "ada@gmail.example"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SECRET_VALUES = (GOOGLE_CLIENT_SECRET, GOOD_CODE, GOOGLE_REFRESH, MS_REFRESH, "ya29.fake-access", "ms-access")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unsigned_jwt(claims: dict[str, Any]) -> str:
    return f"{b64url(b'{}')}.{b64url(json.dumps(claims).encode())}.{b64url(b'sig')}"


@dataclass
class Msg:
    id: str
    raw: bytes
    sender: str = "Alice Example <alice@example.com>"
    subject: str = "Quarterly update"
    snippet: str = "Hello Bob, here are the numbers"
    folder: str = "inbox"
    internal_ms: int = 1_792_000_000_000


@dataclass
class FakeMail:
    requests: list[httpx.Request] = field(default_factory=list)
    gmail: list[Msg] = field(default_factory=list)
    graph: list[Msg] = field(default_factory=list)
    challenge: str | None = None
    google_scope: str = GMAIL_SCOPE
    ms_scope: str = "Mail.Read openid profile email"
    google_refresh_error: str | None = None
    ms_refresh_error: str | None = None
    revoke_status: int = 200
    revoked: list[str] = field(default_factory=list)
    valid_access: set[str] = field(default_factory=set)
    counter: int = 0
    ms_refresh: str = MS_REFRESH + "1"
    rate_limit_path: str | None = None
    redirect_path: str | None = None
    raw_override: bytes | None = None
    size_estimate: int | None = None
    token_forms: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.gmail = [Msg("18c0ffee01", message(), snippet="Hello &#39;Bob&#39;, here are the numbers")]
        self.graph = [Msg("AAMkAGI2-graph-1=", message())]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _access(self, prefix: str) -> str:
        self.counter += 1
        token = f"{prefix}-{self.counter}"
        self.valid_access.add(token)
        return token

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url, host, path = request.url, request.url.host, request.url.path
        if self.redirect_path and path.startswith(self.redirect_path):
            return httpx.Response(302, headers={"Location": "https://evil.example/steal"})
        if self.rate_limit_path and path.startswith(self.rate_limit_path):
            return httpx.Response(429, headers={"Retry-After": "17"}, json={"error": "rate"})
        if host == "oauth2.googleapis.com" and path == "/token":
            return self._google_token(request)
        if host == "oauth2.googleapis.com" and path == "/revoke":
            self.revoked.append(dict(parse_qsl(request.content.decode()))["token"])
            return httpx.Response(self.revoke_status)
        if host == "login.microsoftonline.com" and path.endswith("/oauth2/v2.0/token"):
            return self._ms_token(request)
        if host in {"gmail.googleapis.com", "graph.microsoft.com"}:
            bearer = request.headers.get("authorization", "").removeprefix("Bearer ")
            if bearer not in self.valid_access:
                return httpx.Response(401, json={"error": {"code": 401}})
            return self._gmail(url) if host == "gmail.googleapis.com" else self._graph(url)
        return httpx.Response(404)

    def _check_verifier(self, form: dict[str, str]) -> bool:
        if self.challenge is None:
            return True
        digest = hashlib.sha256(form["code_verifier"].encode()).digest()
        return b64url(digest) == self.challenge

    def _google_token(self, request: httpx.Request) -> httpx.Response:
        form = dict(parse_qsl(request.content.decode()))
        self.token_forms.append(form)
        if form["grant_type"] == "authorization_code":
            if form["code"] != GOOD_CODE or not self._check_verifier(form):
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": self._access("ya29.fake-access"),
                    "expires_in": 3599,
                    "refresh_token": GOOGLE_REFRESH,
                    "scope": self.google_scope,
                    "token_type": "Bearer",
                },
            )
        if self.google_refresh_error or form["refresh_token"] != GOOGLE_REFRESH:
            return httpx.Response(400, json={"error": self.google_refresh_error or "invalid_grant"})
        return httpx.Response(
            200, json={"access_token": self._access("ya29.fake-access"), "expires_in": 3599, "scope": self.google_scope}
        )

    def _ms_token(self, request: httpx.Request) -> httpx.Response:
        form = dict(parse_qsl(request.content.decode()))
        self.token_forms.append(form)
        if form["grant_type"] == "authorization_code":
            if form["code"] != GOOD_CODE or not self._check_verifier(form):
                return httpx.Response(400, json={"error": "invalid_grant"})
        elif self.ms_refresh_error or form["refresh_token"] != self.ms_refresh:
            return httpx.Response(400, json={"error": self.ms_refresh_error or "invalid_grant"})
        self.ms_refresh = MS_REFRESH + str(self.counter + 2)  # Microsoft rotates the refresh token
        return httpx.Response(
            200,
            json={
                "access_token": self._access("ms-access"),
                "expires_in": 3599,
                "refresh_token": self.ms_refresh,
                "scope": self.ms_scope,
                "id_token": unsigned_jwt({"preferred_username": MS_ACCOUNT}),
            },
        )

    def _gmail(self, url: httpx.URL) -> httpx.Response:
        path, query = url.path, parse_qs(url.query.decode())
        if path == "/gmail/v1/users/me/profile":
            return httpx.Response(200, json={"emailAddress": GOOGLE_ACCOUNT})
        if path == "/gmail/v1/users/me/messages":
            wanted = query.get("labelIds", [])
            term = query.get("q", [""])[0].lower()
            rows = [
                m
                for m in self.gmail
                if (not wanted or {"inbox": "INBOX", "junk": "SPAM"}[m.folder] in wanted)
                and (not term or term in m.subject.lower())
            ]
            size = int(query["maxResults"][0])
            start = int(query.get("pageToken", ["0"])[0])
            page = rows[start : start + size]
            body: dict[str, Any] = {"messages": [{"id": m.id, "threadId": m.id} for m in page]}
            if start + size < len(rows):
                body["nextPageToken"] = str(start + size)
            return httpx.Response(200, json=body)
        message_id = unquote(path.rsplit("/", 1)[1])
        found = next((m for m in self.gmail if m.id == message_id), None)
        if found is None:
            return httpx.Response(404, json={"error": {"code": 404}})
        fmt = query["format"][0]
        if fmt == "metadata":
            headers = [{"name": "From", "value": found.sender}, {"name": "Subject", "value": found.subject}]
            return httpx.Response(
                200,
                json={
                    "id": found.id,
                    "snippet": found.snippet,
                    "internalDate": str(found.internal_ms),
                    "payload": {"headers": headers},
                },
            )
        if fmt == "minimal":
            return httpx.Response(200, json={"sizeEstimate": self.size_estimate or len(found.raw)})
        raw = self.raw_override if self.raw_override is not None else found.raw
        return httpx.Response(200, json={"raw": b64url(raw)})

    def _graph(self, url: httpx.URL) -> httpx.Response:
        path, query = url.path, parse_qs(url.query.decode())
        if path.endswith("/$value"):
            message_id = unquote(path.split("/")[-2])
            found = next((m for m in self.graph if m.id == message_id), None)
            if found is None:
                return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})
            return httpx.Response(200, content=self.raw_override if self.raw_override is not None else found.raw)
        folder = {"/v1.0/me/messages": None, "/v1.0/me/mailFolders/inbox/messages": "inbox"}.get(path, "junk")
        term = query.get("$search", [""])[0].strip('"').lower()
        rows = [m for m in self.graph if folder in (None, m.folder) and (not term or term in m.subject.lower())]
        size = int(query["$top"][0]) if "$top" in query else 10
        start = int(query.get("$skip", ["0"])[0])
        page = rows[start : start + size]
        body: dict[str, Any] = {
            "value": [
                {
                    "id": m.id,
                    "subject": m.subject,
                    "from": {"emailAddress": {"name": m.sender.split(" <")[0], "address": "alice@example.com"}},
                    "receivedDateTime": "2026-10-20T09:30:00Z",
                    "bodyPreview": m.snippet,
                }
                for m in page
            ]
        }
        if start + size < len(rows):
            body["@odata.nextLink"] = f"https://graph.microsoft.com{path}?$top={size}&$skip={start + size}"
        return httpx.Response(200, json=body)


def authorization_params(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def configure(service: Any, provider: str) -> None:
    if provider == "gmail":
        service.configure("gmail", GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, None)
    else:
        service.configure("outlook", MS_CLIENT_ID, None, None)


def connect(service: Any, fake: FakeMail, provider: str, host: str | None = None) -> Any:
    """Configure, start and complete a sign-in the way the dashboard does."""
    configure(service, provider)
    host = host or ("127.0.0.1" if provider == "gmail" else "localhost")
    started = service.start(provider, f"http://{host}:8765/mail/connect", acknowledged=True, binding="binding-1")
    fake.challenge = authorization_params(started.authorize_url)["code_challenge"]
    state = authorization_params(started.authorize_url)["state"]
    return service.complete(state, GOOD_CODE, "binding-1")
