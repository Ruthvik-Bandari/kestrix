# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode sign-in with Google and GitHub, access and refresh tokens, and CSRF tokens
(ADR 0004, amended by ADR 0007).

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

A sign-in creates a refresh family (``sid``). The browser holds a 15-minute JWT access token
(``server/tokens.py``) and an opaque 256-bit refresh token; the database stores only
HMAC-SHA256(pepper, refresh token). Each refresh rotates the refresh token; presenting a rotated
one again revokes the family. Every authenticated request verifies the JWT and then checks that its
family is still live, through a 30-second in-process cache that logout, account deletion and reuse
detection update at once. The CSRF token is derived from the ``sid`` with the pepper, so it stays
the same for the family's life and is never stored.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, NoReturn
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from starlette.requests import Request

from .. import __version__
from .settings import HostedSettings, OAuthClient
from .store import FamilyRow, LoginAttempt, Store

if TYPE_CHECKING:
    from .tokens import AccessTokens

ACCESS_COOKIE = "__Host-kx_at"
REFRESH_COOKIE = "__Host-kx_rt"
LOGIN_COOKIE = "__Host-kx_login"
LOGIN_TTL_S = 10 * 60
SESSION_IDLE_S = 7 * 24 * 3600
SESSION_ABSOLUTE_S = 30 * 24 * 3600
REVOCATION_CACHE_TTL_S = 30
REVOCATION_CACHE_MAX = 10_000
MAX_TOKEN = 128
CLOCK_SKEW_S = 5 * 60
WELCOME_PARAM = ("welcome", "created")
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


log = logging.getLogger("kestrix.auth")


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
    """The signed-in caller of one request: a verified access token whose family is live."""

    sid: str = field(repr=False)
    user_id: int
    provider: str
    email: str
    display_name: str
    csrf_token: str = field(repr=False)
    access_expires_at: int


@dataclass(frozen=True)
class LoginStart:
    redirect_url: str
    state: str = field(repr=False)


@dataclass(frozen=True)
class Tokens:
    """A new access token and refresh token, with their lifetimes for the cookies."""

    access_token: str = field(repr=False)
    access_expires_at: int
    access_max_age: int
    refresh_token: str = field(repr=False)
    refresh_max_age: int


@dataclass(frozen=True)
class SignIn:
    tokens: Tokens
    next: str


Intent = Literal["login", "signup"]
AccessProblem = Literal["token_expired", "sign_in_required"]


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


def with_welcome(path: str) -> str:
    """``path`` with ``welcome=created`` added to its query: the one-time "account created" note."""
    parts = urlsplit(path)
    query = [*parse_qsl(parts.query, keep_blank_values=True), WELCOME_PARAM]
    return urlunsplit(("", "", parts.path, urlencode(query), parts.fragment))


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
        from .tokens import AccessTokens  # PyJWT is the hosted extra; local mode never imports it

        self.settings = settings
        self.store = store
        self.client = ProviderClient(transport)
        self.clock = clock
        self.tokens: AccessTokens = AccessTokens(
            settings.jwt_secret, settings.jwt_secret_previous, settings.public_origin, settings.access_ttl_s
        )
        # sid -> (checked at, the live family or None); see family_live.
        self._families: dict[str, tuple[float, FamilyRow | None]] = {}
        self._families_lock = threading.Lock()

    @property
    def providers(self) -> list[str]:
        return [name for name in PROVIDERS if name in self.settings.providers]

    def _now(self) -> int:
        return int(self.clock())

    def _mac(self, data: bytes) -> bytes:
        return hmac.new(self.settings.session_pepper, data, hashlib.sha256).digest()

    def refresh_hash(self, refresh_token: str) -> str:
        return self._mac(b"kx-refresh\x00" + refresh_token.encode()).hex()

    def _state_hash(self, state: str) -> str:
        return self._mac(b"kx-state\x00" + state.encode()).hex()

    def csrf_token(self, sid: str) -> str:
        return _b64url(self._mac(b"kx-csrf-token\x00" + sid.encode()))

    def redirect_uri(self, provider: str) -> str:
        return f"{self.settings.public_origin}/api/auth/callback/{provider}"

    # Sign-in

    def start_login(self, provider: str, next_path: str | None, intent: Intent = "login") -> LoginStart:
        client = self.settings.providers[provider]
        spec = PROVIDERS[provider]
        now = self._now()
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(32) if provider == "google" else None
        self.store.purge(now=now, idle_s=SESSION_IDLE_S, attempt_ttl_s=LOGIN_TTL_S)
        self.store.add_login_attempt(
            self._state_hash(state), LoginAttempt(provider, verifier, nonce, safe_next(next_path), intent, now)
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
        previous_refresh_token: str | None,
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
        signup = attempt.intent == "signup"
        user = self.store.upsert_user(
            identity.provider, identity.subject, identity.email, identity.display_name, now, terms_accepted=signup
        )
        if user.disabled_at is not None:
            raise AuthFailed("account_disabled")
        if previous_refresh_token:
            self._revoke_by_refresh(previous_refresh_token, now)  # a new family at every sign-in
        sid, refresh_token = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        expires_at = now + SESSION_ABSOLUTE_S
        self.store.create_family(sid, user.id, self.refresh_hash(refresh_token), now, expires_at)
        log.info("sign-in provider=%s user=%s new=%s", provider, self.user_tag(user.id), user.created)
        next_path = attempt.next or DEFAULT_NEXT
        if user.created and not signup:
            next_path = with_welcome(next_path)  # created through Log in: show where the terms are, once
        return SignIn(self._tokens(user.id, sid, refresh_token, now, expires_at), next_path)

    def _tokens(self, user_id: int, sid: str, refresh_token: str, now: int, family_expires_at: int) -> Tokens:
        access, access_expires_at = self.tokens.issue(user_id, sid, now)
        return Tokens(access, access_expires_at, self.tokens.ttl_s, refresh_token, max(0, family_expires_at - now))

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

    # Access tokens and refresh families

    def _live(self, family: FamilyRow | None, now: int) -> FamilyRow | None:
        if family is None or family.revoked_at is not None:
            return None
        if now >= family.expires_at or now - family.last_used_at >= SESSION_IDLE_S:
            return None
        return family

    def family_live(self, sid: str) -> FamilyRow | None:
        """The family if it is live, checked against the store at most every 30 seconds per sid.

        Changes made in this process (logout, account deletion, reuse detection) update the cache at
        once; changes made by another process are seen within ``REVOCATION_CACHE_TTL_S``."""
        now = self.clock()
        with self._families_lock:
            cached = self._families.get(sid)
        if cached is not None and now - cached[0] < REVOCATION_CACHE_TTL_S:
            return self._live(cached[1], int(now))
        family = self.store.family(sid)
        with self._families_lock:
            if len(self._families) >= REVOCATION_CACHE_MAX:
                self._families = {
                    key: value for key, value in self._families.items() if now - value[0] < REVOCATION_CACHE_TTL_S
                }
                if len(self._families) >= REVOCATION_CACHE_MAX:
                    self._families.clear()
            self._families[sid] = (now, family)
        return self._live(family, int(now))

    def _forget(self, *sids: str) -> None:
        with self._families_lock:
            for sid in sids:
                self._families.pop(sid, None)

    def authenticate(self, access_token: str | None, *, has_refresh: bool) -> Session | AccessProblem:
        """The caller's session, or why there is none. ``token_expired`` tells the client to refresh:
        the access token expired, or it is missing while a refresh cookie is present."""
        from .tokens import TokenExpired, TokenInvalid

        if not access_token:
            return "token_expired" if has_refresh else "sign_in_required"
        try:
            claims = self.tokens.verify(access_token, self._now())
        except TokenExpired:
            return "token_expired"
        except TokenInvalid:
            return "sign_in_required"
        family = self.family_live(claims.sid)
        if family is None or family.user_id != claims.user_id:
            return "sign_in_required"
        return Session(
            sid=family.sid,
            user_id=family.user_id,
            provider=family.provider,
            email=family.email,
            display_name=family.display_name,
            csrf_token=self.csrf_token(family.sid),
            access_expires_at=claims.expires_at,
        )

    def refreshable(self, refresh_token: str | None) -> FamilyRow | None:
        """The live family whose current refresh token this is. Read-only: nothing rotates."""
        if not refresh_token or len(refresh_token) > MAX_TOKEN:
            return None
        found = self.store.find_refresh(self.refresh_hash(refresh_token))
        if found is None or not found.current:
            return None
        return self._live(found.family, self._now())

    def refresh(self, refresh_token: str | None, csrf_header: str | None) -> Tokens:
        """Rotate the refresh token and issue a new access token.

        Raises ``AuthFailed``: ``csrf_failed`` for a missing or wrong CSRF token, ``refresh_reused`` (after
        revoking the family) for a token that was already rotated, and other codes for an unknown or
        ended family."""
        if not refresh_token or len(refresh_token) > MAX_TOKEN:
            raise AuthFailed("refresh_missing")
        now = self._now()
        old_hash = self.refresh_hash(refresh_token)
        found = self.store.find_refresh(old_hash)
        if found is None:
            raise AuthFailed("refresh_unknown")
        family = found.family
        if not found.current:
            self._reuse_detected(family, now)
        if self._live(family, now) is None:
            raise AuthFailed("refresh_family_ended")
        if not self.csrf_ok(self.csrf_token(family.sid), csrf_header):
            raise AuthFailed("csrf_failed")
        new_token = secrets.token_urlsafe(32)
        if not self.store.rotate_refresh(family.sid, old_hash, self.refresh_hash(new_token), now):
            self._reuse_detected(family, now)  # another request rotated it between the lookup and here
        return self._tokens(family.user_id, family.sid, new_token, now, family.expires_at)

    def _reuse_detected(self, family: FamilyRow, now: int) -> NoReturn:
        self.store.revoke_family(family.sid, now)
        self._forget(family.sid)
        log.warning("refresh token reuse detected; family revoked user=%s", self.user_tag(family.user_id))
        raise AuthFailed("refresh_reused")

    def _revoke_by_refresh(self, refresh_token: str, now: int) -> None:
        family = self.refreshable(refresh_token)
        if family is not None:
            self.revoke(family.sid, now)

    def revoke(self, sid: str, now: int | None = None) -> None:
        self.store.revoke_family(sid, self._now() if now is None else now)
        self._forget(sid)

    @staticmethod
    def csrf_ok(expected: str, header: str | None) -> bool:
        if not header or len(header) > MAX_TOKEN:
            return False
        return hmac.compare_digest(header.encode(), expected.encode())

    def logout(self, session: Session | None, refresh_token: str | None, csrf_header: str | None) -> bool:
        """Revoke the caller's family, found by the access token or else the refresh cookie. False when a
        family was found but the CSRF token does not match it."""
        sid = session.sid if session is not None else None
        user_id = session.user_id if session is not None else None
        if sid is None:
            family = self.refreshable(refresh_token)
            sid, user_id = (family.sid, family.user_id) if family is not None else (None, None)
        if sid is None or user_id is None:
            return True
        if not self.csrf_ok(self.csrf_token(sid), csrf_header):
            return False
        self.revoke(sid)
        log.info("sign-out user=%s", self.user_tag(user_id))
        return True

    def delete_account(self, session: Session) -> None:
        """Remove the user row; its families go with it (``ON DELETE CASCADE``)."""
        self._forget(*self.store.delete_user(session.user_id))
        log.info("account deleted user=%s", self.user_tag(session.user_id))

    def user_tag(self, user_id: int) -> str:
        """A short salted hash of the user id for logs."""
        return hmac.new(self.settings.log_salt, str(user_id).encode(), hashlib.sha256).hexdigest()[:16]

    def host_tag(self, url_or_host: str) -> str:
        return host_tag(self.settings.log_salt, url_or_host)


def host_tag(log_salt: bytes, url_or_host: str) -> str:
    """A short keyed hash of a website check's host for logs (``kestrix hosted hash-host``).

    The host is lower-cased without a trailing dot or IPv6 brackets, so ``https://Site.example./x``
    and ``site.example`` give the same tag. The operator can match a host named in an abuse report
    without the logs ever holding host names.
    """
    value = url_or_host.strip()
    try:
        host = urlsplit(value).hostname if "://" in value else value.strip("[]")
    except ValueError:
        host = None
    if not host:
        return "-"
    normalized = host.lower().rstrip(".")
    return hmac.new(log_salt, b"kx-host\x00" + normalized.encode(), hashlib.sha256).hexdigest()[:16]


def current_session(request: Request) -> Session | None:
    session = getattr(request.state, "session", None)
    return session if isinstance(session, Session) else None
