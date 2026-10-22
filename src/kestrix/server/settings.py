# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Server mode and hosted-mode settings, read from the environment (ADR 0004).

``KESTRIX_MODE=local`` (the default) needs nothing else. ``KESTRIX_MODE=hosted`` needs a
public https origin, a session pepper, a JWT signing secret (ADR 0007), a result-history
encryption key (ADR 0008), the ``kestrix[hosted]`` extra and at least one sign-in provider; a missing or
malformed value raises :class:`SettingsError` so the server refuses to start rather than
run with a weaker configuration. Secret values are kept out of ``repr``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import importlib.util
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from ..core import config

MIB = 1024 * 1024
MIN_PEPPER_BYTES = 32
MIN_JWT_SECRET_BYTES = 32
MIN_LOG_SALT_BYTES = 16
MAX_ABUSE_CONTACT = 200
HISTORY_KEY_BYTES = 32
HISTORY_KEY_HINT = 'generate one with: python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"'
# Read once at start-up; ``kestrix serve-hosted`` then removes them from the process environment
# so no child process (analysis workers, a restarted fork server) can inherit them.
SECRET_ENV = (
    "KESTRIX_SESSION_PEPPER",
    "KESTRIX_JWT_SECRET",
    "KESTRIX_JWT_SECRET_PREVIOUS",
    "KESTRIX_HISTORY_KEY",
    "KESTRIX_HISTORY_KEY_PREVIOUS",
    "KESTRIX_LOG_SALT",
    "KESTRIX_GOOGLE_CLIENT_SECRET",
    "KESTRIX_GITHUB_CLIENT_SECRET",
    "ANTHROPIC_API_KEY",
)
PROVIDER_ENV = {
    "google": ("KESTRIX_GOOGLE_CLIENT_ID", "KESTRIX_GOOGLE_CLIENT_SECRET"),
    "github": ("KESTRIX_GITHUB_CLIENT_ID", "KESTRIX_GITHUB_CLIENT_SECRET"),
}


class SettingsError(ValueError):
    """The requested mode is misconfigured; the server must not start."""


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class HostedSettings:
    public_origin: str  # normalized, e.g. "https://kestrix.example.org"
    public_host: str  # the origin's host name, the only allowed Host header value
    db_path: Path
    session_pepper: bytes = field(repr=False)
    log_salt: bytes = field(repr=False)
    jwt_secret: bytes = field(repr=False)
    # Accepted only to verify access tokens signed before a secret rotation.
    jwt_secret_previous: bytes | None = field(default=None, repr=False)
    # AES-256-GCM key for stored result reports (ADR 0008); the previous one only decrypts.
    history_key: bytes = field(default=b"", repr=False)
    history_key_previous: bytes | None = field(default=None, repr=False)
    providers: Mapping[str, OAuthClient] = field(default_factory=dict)
    trust_proxy_headers: bool = False
    # A header that the platform's proxy always overwrites with the client address (Fly: Fly-Client-IP).
    client_ip_header: str | None = None
    abuse_contact: str | None = None
    # Owner choice (docs/deploy.md): add ``preload`` to HSTS. Off by default because preloading
    # covers every subdomain and is slow to undo.
    hsts_preload: bool = False
    # Fixed service limits (not read from the environment); tests shrink them.
    max_mail_bytes: int = 10 * MIB
    max_file_bytes: int = 10 * MIB
    max_concurrent_analyses: int = 2
    max_concurrent_webchecks: int = 8
    analysis_cpu_s: int = 10
    analysis_memory_bytes: int = 384 * MIB
    analysis_wall_s: float = 20.0
    access_ttl_s: int = 15 * 60
    # Deleting an account needs a sign-in at most this old (the session's own sign-in, not its last refresh).
    reauth_window_s: int = 10 * 60
    # Slow-request limits for request bodies (server/app.py ``_StreamedBodyLimit``): longest wait for
    # the next piece of a body, and longest total time to receive one (uploads get the larger bound).
    body_idle_s: float = 10.0
    body_total_s: float = 30.0
    upload_total_s: float = 120.0
    # Where the rate-limit counters live: "memory" (this process) or "sqlite" (shared by every process
    # that opens the same database folder; docs/hosted.md).
    rate_limit_store: Literal["memory", "sqlite"] = "memory"


@dataclass(frozen=True)
class Settings:
    mode: Literal["local", "hosted"] = "local"
    hosted: HostedSettings | None = None


def _origin(value: str) -> tuple[str, str]:
    """Return ``(origin, host)`` for an https origin with no path, query or credentials."""
    parts = urlsplit(value.strip())
    if parts.scheme != "https":
        raise SettingsError("KESTRIX_PUBLIC_ORIGIN must start with https://")
    if (
        not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise SettingsError("KESTRIX_PUBLIC_ORIGIN must be only a scheme and host, such as https://kestrix.example.org")
    try:
        port = parts.port
    except ValueError:
        raise SettingsError("KESTRIX_PUBLIC_ORIGIN has an invalid port") from None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = host if port in {None, 443} else f"{host}:{port}"
    return f"https://{netloc}", host


def _flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().lower()
    if value in {"", "0", "false", "no"}:
        return False
    if value in {"1", "true", "yes"}:
        return True
    raise SettingsError(f"{name} must be 1 or 0")


def _providers(env: Mapping[str, str]) -> dict[str, OAuthClient]:
    providers: dict[str, OAuthClient] = {}
    for name, (id_var, secret_var) in PROVIDER_ENV.items():
        client_id, secret = env.get(id_var, "").strip(), env.get(secret_var, "").strip()
        if client_id and secret:
            providers[name] = OAuthClient(client_id, secret)
        elif client_id or secret:
            raise SettingsError(f"set both {id_var} and {secret_var} to enable {name} sign-in, or neither")
    if not providers:
        raise SettingsError("hosted mode needs at least one sign-in provider (Google or GitHub client id and secret)")
    return providers


def _client_ip_header(env: Mapping[str, str]) -> str | None:
    value = env.get("KESTRIX_CLIENT_IP_HEADER", "").strip()
    if not value:
        return None
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", value):
        raise SettingsError("KESTRIX_CLIENT_IP_HEADER must be a header name such as Fly-Client-IP")
    if _flag(env, "KESTRIX_TRUST_PROXY_HEADERS"):
        raise SettingsError("set KESTRIX_CLIENT_IP_HEADER or KESTRIX_TRUST_PROXY_HEADERS, not both")
    return value.lower()


def _rate_limit_store(env: Mapping[str, str]) -> Literal["memory", "sqlite"]:
    value = env.get("KESTRIX_RATE_LIMIT_STORE", "").strip().lower() or "memory"
    if value == "memory":
        return "memory"
    if value == "sqlite":
        return "sqlite"
    raise SettingsError("KESTRIX_RATE_LIMIT_STORE must be memory or sqlite")


def _abuse_contact(env: Mapping[str, str]) -> str | None:
    value = env.get("KESTRIX_ABUSE_CONTACT", "").strip()
    if not value:
        return None
    if len(value) > MAX_ABUSE_CONTACT or not all(32 <= ord(ch) < 127 for ch in value):
        raise SettingsError(f"KESTRIX_ABUSE_CONTACT must be printable ASCII of at most {MAX_ABUSE_CONTACT} characters")
    return value


def _jwt_secrets(env: Mapping[str, str], pepper: bytes) -> tuple[bytes, bytes | None]:
    hint = 'generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
    secret = env.get("KESTRIX_JWT_SECRET", "").encode()
    if len(secret) < MIN_JWT_SECRET_BYTES:
        raise SettingsError(f"hosted mode needs KESTRIX_JWT_SECRET of at least {MIN_JWT_SECRET_BYTES} bytes; {hint}")
    previous = env.get("KESTRIX_JWT_SECRET_PREVIOUS", "").encode() or None
    if previous is not None and len(previous) < MIN_JWT_SECRET_BYTES:
        raise SettingsError(f"KESTRIX_JWT_SECRET_PREVIOUS must be at least {MIN_JWT_SECRET_BYTES} bytes")
    if hmac.compare_digest(secret, pepper) or (previous is not None and hmac.compare_digest(secret, previous)):
        raise SettingsError(
            "KESTRIX_JWT_SECRET must differ from KESTRIX_SESSION_PEPPER and KESTRIX_JWT_SECRET_PREVIOUS"
        )
    if importlib.util.find_spec("jwt") is None:
        raise SettingsError("hosted mode needs the hosted extra: pip install 'kestrix[hosted]'")
    return secret, previous


def _history_key(env: Mapping[str, str], name: str, *, required: bool) -> bytes | None:
    value = env.get(name, "").strip()
    if not value:
        if required:
            raise SettingsError(
                f"hosted mode needs {name}, {HISTORY_KEY_BYTES} random bytes in base64; {HISTORY_KEY_HINT}"
            )
        return None
    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != HISTORY_KEY_BYTES:
        raise SettingsError(f"{name} must be exactly {HISTORY_KEY_BYTES} bytes in base64; {HISTORY_KEY_HINT}")
    return key


def _history_keys(env: Mapping[str, str]) -> tuple[bytes, bytes | None]:
    key = _history_key(env, "KESTRIX_HISTORY_KEY", required=True)
    assert key is not None
    previous = _history_key(env, "KESTRIX_HISTORY_KEY_PREVIOUS", required=False)
    if importlib.util.find_spec("cryptography") is None:
        raise SettingsError("hosted mode needs the hosted extra: pip install 'kestrix[hosted]'")
    if previous is not None and hmac.compare_digest(key, previous):
        raise SettingsError("KESTRIX_HISTORY_KEY_PREVIOUS must differ from KESTRIX_HISTORY_KEY")
    return key, previous


def load_settings(env: Mapping[str, str] | None = None, *, mode: str | None = None) -> Settings:
    """Read the settings; ``mode`` overrides ``KESTRIX_MODE`` (``kestrix serve-hosted`` forces hosted)."""
    env = os.environ if env is None else env
    chosen = (mode if mode is not None else env.get("KESTRIX_MODE", "")).strip().lower() or "local"
    if chosen == "local":
        return Settings()
    if chosen != "hosted":
        raise SettingsError("KESTRIX_MODE must be 'local' or 'hosted'")
    origin_value = env.get("KESTRIX_PUBLIC_ORIGIN", "").strip()
    if not origin_value:
        raise SettingsError("hosted mode needs KESTRIX_PUBLIC_ORIGIN, such as https://kestrix.example.org")
    origin, host = _origin(origin_value)
    pepper = env.get("KESTRIX_SESSION_PEPPER", "").encode()
    if len(pepper) < MIN_PEPPER_BYTES:
        raise SettingsError(f"hosted mode needs KESTRIX_SESSION_PEPPER of at least {MIN_PEPPER_BYTES} bytes")
    salt_value = env.get("KESTRIX_LOG_SALT", "").encode()
    if salt_value and len(salt_value) < MIN_LOG_SALT_BYTES:
        raise SettingsError(f"KESTRIX_LOG_SALT must be at least {MIN_LOG_SALT_BYTES} bytes")
    # Without its own salt, the log salt is derived from the pepper, so it is stable across restarts
    # but reveals nothing about the pepper.
    log_salt = salt_value or hmac.new(pepper, b"kestrix-log-salt", hashlib.sha256).digest()
    jwt_secret, jwt_secret_previous = _jwt_secrets(env, pepper)
    history_key, history_key_previous = _history_keys(env)
    db_value = env.get("KESTRIX_DB", "").strip()
    return Settings(
        mode="hosted",
        hosted=HostedSettings(
            public_origin=origin,
            public_host=host,
            db_path=Path(db_value) if db_value else config.config_dir() / "hosted.sqlite3",
            session_pepper=pepper,
            log_salt=log_salt,
            jwt_secret=jwt_secret,
            jwt_secret_previous=jwt_secret_previous,
            history_key=history_key,
            history_key_previous=history_key_previous,
            providers=_providers(env),
            trust_proxy_headers=_flag(env, "KESTRIX_TRUST_PROXY_HEADERS"),
            client_ip_header=_client_ip_header(env),
            abuse_contact=_abuse_contact(env),
            rate_limit_store=_rate_limit_store(env),
            hsts_preload=_flag(env, "KESTRIX_HSTS_PRELOAD"),
        ),
    )
