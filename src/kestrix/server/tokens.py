# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode access tokens: HS256 JWTs signed and checked with PyJWT (ADR 0007).

PyJWT checks the signature with the algorithm pinned to HS256, the issuer, the audience and that
every claim is present. The time claims (``exp``, ``nbf``, ``iat``) are then checked here against
the service clock, with 30 seconds of leeway, because PyJWT reads the wall clock directly and the
tests (and the click-through harness) run on a controllable clock.

The ``kid`` header names the key: a keyed hash of the secret, so it reveals nothing about it.
``KESTRIX_JWT_SECRET_PREVIOUS`` is accepted for verification only; new tokens always use the
current secret. This module needs the ``kestrix[hosted]`` extra; ``server/auth.py`` imports it
only when a hosted ``AuthService`` is built, so local mode never imports PyJWT.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

import jwt

AUDIENCE = "kestrix"
ALGORITHM = "HS256"
LEEWAY_S = 30
REQUIRED_CLAIMS = ("exp", "iat", "nbf", "iss", "aud", "sub", "sid", "jti")
MAX_TOKEN_CHARS = 4096


class TokenExpired(Exception):
    """The token's signature and claims are valid, but it has expired."""


class TokenInvalid(Exception):
    """Anything else wrong with the token. The message is a fixed code that is safe to log."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: int
    sid: str
    expires_at: int


def key_id(secret: bytes) -> str:
    return hmac.new(secret, b"kestrix-jwt-kid", hashlib.sha256).hexdigest()[:16]


class AccessTokens:
    def __init__(self, secret: bytes, previous: bytes | None, issuer: str, ttl_s: int) -> None:
        self._kid = key_id(secret)
        self._secret = secret
        self._keys = {self._kid: secret}
        if previous is not None:
            self._keys[key_id(previous)] = previous
        self.issuer = issuer
        self.ttl_s = ttl_s

    def issue(self, user_id: int, sid: str, now: int) -> tuple[str, int]:
        """A new access token for this family, and when it expires."""
        expires_at = now + self.ttl_s
        claims = {
            "iss": self.issuer,
            "aud": AUDIENCE,
            "sub": str(user_id),
            "sid": sid,
            "iat": now,
            "nbf": now,
            "exp": expires_at,
            "jti": secrets.token_urlsafe(16),
        }
        return jwt.encode(claims, self._secret, algorithm=ALGORITHM, headers={"kid": self._kid}), expires_at

    def verify(self, token: str, now: int) -> AccessClaims:
        if len(token) > MAX_TOKEN_CHARS:
            raise TokenInvalid("token_too_long")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise TokenInvalid("token_malformed") from None
        kid = header.get("kid")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise TokenInvalid("unknown_kid")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=self.issuer,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    # Checked below against the service clock.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidTokenError:
            raise TokenInvalid("token_rejected") from None
        exp, nbf, iat = claims["exp"], claims["nbf"], claims["iat"]
        sub, sid = claims["sub"], claims["sid"]
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (exp, nbf, iat)):
            raise TokenInvalid("bad_time_claims")
        if not isinstance(sub, str) or not sub.isdigit() or not isinstance(sid, str) or not sid:
            raise TokenInvalid("bad_subject")
        if nbf > now + LEEWAY_S or iat > now + LEEWAY_S:
            raise TokenInvalid("not_yet_valid")
        if exp <= now - LEEWAY_S:
            raise TokenExpired
        return AccessClaims(int(sub), sid, exp)
