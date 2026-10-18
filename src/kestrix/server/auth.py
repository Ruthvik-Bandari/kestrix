# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode sign-in with Google and GitHub, sessions and CSRF tokens (ADR 0004).

Sign-in is the OAuth 2.0 authorization-code flow with PKCE (S256) and a random ``state``;
Google adds an OpenID Connect ``nonce``. The pending attempt is stored server-side, keyed
by a keyed hash of ``state``, for at most ten minutes and used once. The ``state`` is also
set in a short-lived ``__Host-`` cookie and must match on the callback, which binds the
flow to the browser that started it (login CSRF).

Google's ID token is not signature-checked. It is received directly from Google's token
endpoint over a verified TLS connection in exchange for our code and client secret, which
OpenID Connect Core 1.0 section 3.1.3.7 (rule 6) allows in place of checking the
signature. Its claims are still validated: issuer, audience, expiry, issue time, nonce and
a verified email.

Session ids are 256-bit random values. The database stores only HMAC-SHA256(pepper, id).
The CSRF token is derived from the session id with the same pepper, so it can be shown to
the signed-in page without being stored; the database keeps only its keyed hash.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from starlette.requests import Request

from .. import __version__
from .settings import HostedSettings, OAuthClient
from .store import LoginAttempt, Store

SESSION_COOKIE = "__Host-kx_session"
LOGIN_COOKIE = "__Host-kx_login"
LOGIN_TTL_S = 10 * 60
SESSION_IDLE_S = 7 * 24 * 3600
SESSION_ABSOLUTE_S = 30 * 24 * 3600
TOUCH_INTERVAL_S = 5 * 60
CLOCK_SKEW_S = 5 * 60
DEFAULT_NEXT = "/app"
FAILED_REDIRECT = "/welcome?signin=failed"
MAX_NEXT = 512
MAX_PARAM = 2048
MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
PROVIDER_TIMEOUT_S = 10.0
ALLOWED_PROVIDER_HOSTS = frozenset({"accounts.google.com", "oauth2.googleapis.com", "github.com", "api.github.com"})
GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
_USER_AGENT = f"kestrix-hosted/{__version__}"


@dataclass(frozen=True)
class ProviderSpec:
    authorize_url: str
    exchange_url: str
    scope: str


PROVIDERS = {
    "google": ProviderSpec(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        exchange_url="https://oauth2.googleapis.com/token",
        scope="openid email profile",
    ),
    "github": ProviderSpec(
        authorize_url="https://github.com/login/oauth/authorize",
        exchange_url="https://github.com/login/oauth/access_token",
        scope="read:user user:email",
    ),
}
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


class AuthFailed(Exception):
    """A sign-in step failed. ``code`` is a fixed reason code that is safe to log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Identity:
    provider: str
    subject: str
    email: str
    display_name: str


@dataclass(frozen=True)
class Session:
    id_hash: str = field(repr=False)
    user_id: int
    provider: str
    email: str
    display_name: str
    csrf_token: str = field(repr=False)
    csrf_token_hash: str = field(repr=False)


@dataclass(frozen=True)
class LoginStart:
    redirect_url: str
    state: str = field(repr=False)


@dataclass(frozen=True)
class SignIn:
    session_id: str = field(repr=False)
    next: str


def safe_next(value: str | None) -> str | None:
    """A same-origin relative path to return to after sign-in, or ``None``.

    Refuses anything a browser could treat as another origin: ``//host``, backslashes
    (browsers read ``/\\host`` as ``//host``), control characters and whitespace (browsers
    strip tabs and newlines), and anything with a scheme or host.
    """
    if not value or len(value) > MAX_NEXT or not value.startswith("/") or value.startswith("//"):
        return None
    if "\\" in value or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def _text(value: object, limit: int) -> str | None:
    """A non-empty printable string of at most ``limit`` characters, else ``None``."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return cleaned[:limit] or None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def jwt_claims(token: object) -> dict[str, Any]:
    """Decode a JWT's claims without checking its signature (see the module docstring for why)."""
    if not isinstance(token, str) or len(token) > 16 * 1024:
        raise AuthFailed("id_token_malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthFailed("id_token_malformed")
    try:
        claims = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError):
        raise AuthFailed("id_token_malformed") from None
    if not isinstance(claims, dict):
        raise AuthFailed("id_token_malformed")
    return claims


class ProviderClient:
    """HTTPS client restricted to the providers' fixed hosts.

    No redirects, no environment proxies, verified TLS, a timeout and a response size cap.
    The hosts are fixed provider endpoints, so ``netguard``'s private-address check does not
    apply; the allowlist is the control.
    """

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def request(
        self, method: str, url: str, *, data: Mapping[str, str] | None = None, headers: Mapping[str, str] | None = None
    ) -> object:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_PROVIDER_HOSTS or parts.port not in {None, 443}:
            raise AuthFailed("provider_host_not_allowed")
        merged = {"Accept": "application/json", "User-Agent": _USER_AGENT, **(headers or {})}
        try:
            with (
                httpx.Client(
                    transport=self._transport,
                    follow_redirects=False,
                    trust_env=False,
                    verify=httpx.create_ssl_context(),
                    timeout=PROVIDER_TIMEOUT_S,
                ) as client,
                client.stream(method, url, data=data, headers=merged) as resp,
            ):
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_PROVIDER_RESPONSE_BYTES:
                        raise AuthFailed("provider_response_too_large")
                status = resp.status_code
        except httpx.HTTPError:
            raise AuthFailed("provider_unreachable") from None
        if not 200 <= status < 300:
            raise AuthFailed("provider_http_error")
        try:
            return json.loads(body)
        except ValueError:
            raise AuthFailed("provider_bad_json") from None


class AuthService:
    def __init__(
        self,
        settings: HostedSettings,
        store: Store,
        *,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.store = store
        self.client = ProviderClient(transport)
        self.clock = clock

    @property
    def providers(self) -> list[str]:
        return [name for name in PROVIDERS if name in self.settings.providers]

    def _now(self) -> int:
        return int(self.clock())

    def _mac(self, data: bytes) -> bytes:
        return hmac.new(self.settings.session_pepper, data, hashlib.sha256).digest()

    def session_hash(self, session_id: str) -> str:
        return self._mac(session_id.encode()).hex()

    def _state_hash(self, state: str) -> str:
        return self._mac(b"kx-state\x00" + state.encode()).hex()

    def _csrf_token(self, session_id: str) -> str:
        return _b64url(self._mac(b"kx-csrf-token\x00" + session_id.encode()))

    def _csrf_hash(self, token: str) -> str:
        return self._mac(b"kx-csrf-hash\x00" + token.encode()).hex()

    def redirect_uri(self, provider: str) -> str:
        return f"{self.settings.public_origin}/api/auth/callback/{provider}"

    # Sign-in

    def start_login(self, provider: str, next_path: str | None) -> LoginStart:
        client = self.settings.providers[provider]
        spec = PROVIDERS[provider]
        now = self._now()
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(32) if provider == "google" else None
        self.store.purge(now=now, idle_s=SESSION_IDLE_S, attempt_ttl_s=LOGIN_TTL_S)
        self.store.add_login_attempt(
            self._state_hash(state), LoginAttempt(provider, verifier, nonce, safe_next(next_path), now)
        )
        params = {
            "client_id": client.client_id,
            "redirect_uri": self.redirect_uri(provider),
            "response_type": "code",
            "scope": spec.scope,
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        if nonce is not None:
            params["nonce"] = nonce
        return LoginStart(f"{spec.authorize_url}?{urlencode(params)}", state)

    def finish_login(
        self,
        provider: str,
        *,
        state: str | None,
        code: str | None,
        error: str | None,
        bound_state: str | None,
        previous_session_id: str | None,
    ) -> SignIn:
        if provider not in self.settings.providers:
            raise AuthFailed("unknown_provider")
        if not state or len(state) > MAX_PARAM:
            raise AuthFailed("missing_state")
        attempt = self.store.take_login_attempt(self._state_hash(state))
        if attempt is None:
            raise AuthFailed("unknown_state")
        if bound_state is None or not hmac.compare_digest(bound_state.encode(), state.encode()):
            raise AuthFailed("state_not_bound_to_browser")
        if attempt.provider != provider:
            raise AuthFailed("provider_mismatch")
        now = self._now()
        if now - attempt.created_at > LOGIN_TTL_S:
            raise AuthFailed("attempt_expired")
        if error or not code or len(code) > MAX_PARAM:
            raise AuthFailed("provider_denied")
        client = self.settings.providers[provider]
        if provider == "google":
            identity = self._google_identity(client, code, attempt, now)
        else:
            identity = self._github_identity(client, code, attempt)
        user_id = self.store.upsert_user(
            identity.provider, identity.subject, identity.email, identity.display_name, now
        )
        if previous_session_id:
            self.store.delete_session(self.session_hash(previous_session_id))  # rotate on sign-in
        session_id = secrets.token_urlsafe(32)
        self.store.create_session(
            self.session_hash(session_id),
            user_id,
            self._csrf_hash(self._csrf_token(session_id)),
            now,
            now + SESSION_ABSOLUTE_S,
        )
        return SignIn(session_id, attempt.next or DEFAULT_NEXT)

    def _exchange(self, provider: str, client: OAuthClient, code: str, verifier: str) -> dict[str, Any]:
        token = self.client.request(
            "POST",
            PROVIDERS[provider].exchange_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri(provider),
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "code_verifier": verifier,
            },
        )
        if not isinstance(token, dict):
            raise AuthFailed("token_response_malformed")
        return token

    def _google_identity(self, client: OAuthClient, code: str, attempt: LoginAttempt, now: int) -> Identity:
        claims = jwt_claims(self._exchange("google", client, code, attempt.verifier).get("id_token"))
        if claims.get("iss") not in GOOGLE_ISSUERS:
            raise AuthFailed("id_token_wrong_issuer")
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if client.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") != client.client_id):
            raise AuthFailed("id_token_wrong_audience")
        exp, iat = _int(claims.get("exp")), _int(claims.get("iat"))
        if (
            exp is None
            or iat is None
            or exp <= now
            or iat > now + CLOCK_SKEW_S
            or iat < now - LOGIN_TTL_S - CLOCK_SKEW_S
        ):
            raise AuthFailed("id_token_expired_or_not_yet_valid")
        nonce = claims.get("nonce")
        if (
            not isinstance(nonce, str)
            or attempt.nonce is None
            or not hmac.compare_digest(nonce.encode(), attempt.nonce.encode())
        ):
            raise AuthFailed("id_token_wrong_nonce")
        if claims.get("email_verified") is not True:
            raise AuthFailed("email_not_verified")
        subject, email = _text(claims.get("sub"), 255), _text(claims.get("email"), 320)
        if subject is None or email is None:
            raise AuthFailed("id_token_missing_identity")
        return Identity("google", subject, email, _text(claims.get("name"), 200) or email)

    def _github_identity(self, client: OAuthClient, code: str, attempt: LoginAttempt) -> Identity:
        access = self._exchange("github", client, code, attempt.verifier).get("access_token")
        if not isinstance(access, str) or not access:
            raise AuthFailed("token_exchange_failed")
        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        user = self.client.request("GET", GITHUB_USER_URL, headers=headers)
        emails = self.client.request("GET", GITHUB_EMAILS_URL, headers=headers)
        if not isinstance(user, dict) or not isinstance(emails, list):
            raise AuthFailed("github_response_malformed")
        user_id, login = _int(user.get("id")), _text(user.get("login"), 100)
        if user_id is None or login is None:
            raise AuthFailed("github_response_malformed")
        email = next(
            (
                _text(item.get("email"), 320)
                for item in emails
                if isinstance(item, dict) and item.get("primary") is True and item.get("verified") is True
            ),
            None,
        )
        if email is None:
            raise AuthFailed("email_not_verified")
        return Identity("github", str(user_id), email, _text(user.get("name"), 200) or login)

    # Sessions

    def session_from_cookie(self, session_id: str | None) -> Session | None:
        """The live session for this cookie value, enforcing idle and absolute expiry."""
        if not session_id or len(session_id) > 128:
            return None
        id_hash = self.session_hash(session_id)
        row = self.store.get_session(id_hash)
        if row is None:
            return None
        now = self._now()
        if now >= row.expires_at or now - row.last_seen_at >= SESSION_IDLE_S:
            self.store.delete_session(id_hash)
            return None
        if now - row.last_seen_at >= TOUCH_INTERVAL_S:
            self.store.touch_session(id_hash, now)
        return Session(
            id_hash=id_hash,
            user_id=row.user_id,
            provider=row.provider,
            email=row.email,
            display_name=row.display_name,
            csrf_token=self._csrf_token(session_id),
            csrf_token_hash=row.csrf_token_hash,
        )

    def csrf_ok(self, session: Session, header: str | None) -> bool:
        if not header or len(header) > 128:
            return False
        return hmac.compare_digest(self._csrf_hash(header), session.csrf_token_hash)

    def logout(self, session: Session) -> None:
        self.store.delete_session(session.id_hash)

    def delete_account(self, session: Session) -> None:
        """Remove the user row; its sessions go with it (``ON DELETE CASCADE``)."""
        self.store.delete_user(session.user_id)

    def user_tag(self, user_id: int) -> str:
        """A short salted hash of the user id for logs."""
        return hmac.new(self.settings.log_salt, str(user_id).encode(), hashlib.sha256).hexdigest()[:16]


def current_session(request: Request) -> Session | None:
    session = getattr(request.state, "session", None)
    return session if isinstance(session, Session) else None
