# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Stored settings of the mailbox connector: the user's own OAuth app and the refresh token.

Everything lives in the 0600 `secrets.json` (`core/config.py`) under `mail_<provider>_*` keys. Nothing
here is logged, returned by a route or written to evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...core import config
from ...core.errors import Reason, Rejected
from .models import Provider

PROVIDERS: tuple[Provider, ...] = ("gmail", "outlook")
_CLIENT_ID = re.compile(r"[A-Za-z0-9._-]{8,200}")
_GUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_SECRET = re.compile(r"[\x21-\x7e]{6,256}")
_TENANT = re.compile(r"[A-Za-z0-9.-]{1,128}")
DEFAULT_TENANT = "common"


def _key(provider: Provider, name: str) -> str:
    return f"mail_{provider}_{name}"


@dataclass(frozen=True)
class AppConfig:
    client_id: str
    client_secret: str | None
    tenant: str


def validate_app(provider: Provider, client_id: str, client_secret: str | None, tenant: str | None) -> AppConfig:
    client_id = client_id.strip()
    if not _CLIENT_ID.fullmatch(client_id) or (provider == "outlook" and not _GUID.fullmatch(client_id)):
        what = "the Application (client) ID, a GUID" if provider == "outlook" else "the OAuth client ID"
        raise Rejected(Reason.INVALID_INPUT, f"client_id must be {what}")
    secret = client_secret.strip() if client_secret else None
    if secret is not None and not _SECRET.fullmatch(secret):
        raise Rejected(Reason.INVALID_INPUT, "client_secret has an unexpected format")
    if provider == "outlook" and secret is not None:
        raise Rejected(Reason.INVALID_INPUT, "a Microsoft public client uses no client secret")
    chosen = (tenant or DEFAULT_TENANT).strip()
    if provider == "gmail":
        chosen = DEFAULT_TENANT
    elif not _TENANT.fullmatch(chosen):
        raise Rejected(Reason.INVALID_INPUT, "tenant must be common, organizations, consumers, a tenant ID or a domain")
    return AppConfig(client_id, secret, chosen)


def save_app(provider: Provider, app: AppConfig) -> None:
    config.set_secret(_key(provider, "client_id"), app.client_id)
    config.set_secret(_key(provider, "client_secret"), app.client_secret)
    config.set_secret(_key(provider, "tenant"), app.tenant)


def load_app(provider: Provider) -> AppConfig | None:
    client_id = config.get_secret(_key(provider, "client_id"))
    if not client_id:
        return None
    return AppConfig(
        client_id,
        config.get_secret(_key(provider, "client_secret")),
        config.get_secret(_key(provider, "tenant")) or DEFAULT_TENANT,
    )


def refresh_token(provider: Provider) -> str | None:
    return config.get_secret(_key(provider, "refresh_token"))


def save_refresh_token(provider: Provider, token: str) -> None:
    config.set_secret(_key(provider, "refresh_token"), token)


def account(provider: Provider) -> str | None:
    return config.get_secret(_key(provider, "account"))


def save_account(provider: Provider, label: str | None) -> None:
    config.set_secret(_key(provider, "account"), label)


def clear_tokens(provider: Provider) -> None:
    config.set_secret(_key(provider, "refresh_token"), None)
    config.set_secret(_key(provider, "account"), None)


def clear_app(provider: Provider) -> None:
    for name in ("client_id", "client_secret", "tenant"):
        config.set_secret(_key(provider, name), None)
