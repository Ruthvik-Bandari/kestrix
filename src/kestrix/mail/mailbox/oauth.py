# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""OAuth 2.0 authorization code flow with PKCE for installed apps (RFC 7636, RFC 8252).

Endpoints and parameters follow Google's native-app guide and Microsoft's authorization code flow
(links in ADR 0009). Client secrets, codes and tokens stay inside these functions' arguments and results;
they are never logged and never put in an error message.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from urllib.parse import unquote, urlencode

from ...core.errors import RateLimited, Reason, Rejected
from .http import MailboxHttp, Reply
from .models import Provider
from .providers import DEFAULT_RETRY_S, GMAIL_SCOPE, GRAPH_SCOPE
from .store import AppConfig

GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"  # noqa: S105 - an endpoint URL, not a credential
GOOGLE_REVOKE = "https://oauth2.googleapis.com/revoke"
MICROSOFT_BASE = "https://login.microsoftonline.com"
MICROSOFT_SCOPES = f"openid profile offline_access {GRAPH_SCOPE}"
# Graph answers with short names ("Mail.Read") or full URLs; the field is optional in Microsoft's responses.
REQUIRED_SCOPE = {"gmail": {GMAIL_SCOPE}, "outlook": {GRAPH_SCOPE.lower(), "mail.read"}}
MAX_EXPIRES_IN = 86_400


class ReconnectRequired(Exception):
    """The provider rejected the refresh token (revoked, expired, or Google's 7-day Testing limit)."""


@dataclass(frozen=True)
class TokenGrant:
    access_token: str
    expires_in: int
    refresh_token: str | None
    scope: str
    id_token: str | None


def pkce_pair() -> tuple[str, str]:
    """A 64-character code verifier and its S256 challenge."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def token_url(provider: Provider, app: AppConfig) -> str:
    return GOOGLE_TOKEN if provider == "gmail" else f"{MICROSOFT_BASE}/{app.tenant}/oauth2/v2.0/token"


def authorize_url(provider: Provider, app: AppConfig, redirect_uri: str, state: str, challenge: str) -> str:
    params = {
        "client_id": app.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if provider == "gmail":
        params |= {"scope": GMAIL_SCOPE, "access_type": "offline", "prompt": "consent"}
        return f"{GOOGLE_AUTHORIZE}?{urlencode(params)}"
    params |= {"scope": MICROSOFT_SCOPES, "response_mode": "query", "prompt": "select_account"}
    return f"{MICROSOFT_BASE}/{app.tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


def _error_code(reply: Reply) -> str:
    try:
        code = json.loads(reply.body).get("error")
    except (ValueError, AttributeError):
        return ""
    return code if isinstance(code, str) and len(code) <= 64 and code.replace("_", "").isalnum() else ""


def _grant(reply: Reply, provider: Provider, *, on_invalid_grant: Rejected | None) -> TokenGrant:
    """Parse a token response, or raise the outcome for its error. ``on_invalid_grant``: raised for invalid_grant
    (None means a refresh: the caller must reconnect)."""
    if reply.status == 429:
        raise RateLimited("the sign-in service is limiting requests; try again later", DEFAULT_RETRY_S)
    if reply.status >= 500:
        raise Rejected(Reason.UPSTREAM_ERROR, "the sign-in service had an error; try again later")
    if reply.status != 200:
        code = _error_code(reply)
        if code == "invalid_grant":
            if on_invalid_grant is None:
                raise ReconnectRequired
            raise on_invalid_grant
        if code in {"invalid_client", "unauthorized_client"}:
            raise Rejected(
                Reason.UPSTREAM_ERROR,
                "the provider rejected the client credentials; check the client ID"
                + (" and client secret" if provider == "gmail" else "")
                + " of your app registration",
            )
        raise Rejected(Reason.UPSTREAM_ERROR, f"the sign-in service refused the request ({code or reply.status})")
    try:
        body = json.loads(reply.body)
        access, expires = body["access_token"], int(body["expires_in"])
    except (ValueError, KeyError, TypeError):
        raise Rejected(Reason.UPSTREAM_ERROR, "the sign-in service's answer was not understood") from None
    refresh, scope, id_token = body.get("refresh_token"), body.get("scope"), body.get("id_token")
    if not isinstance(access, str) or not access or not 0 < expires <= MAX_EXPIRES_IN:
        raise Rejected(Reason.UPSTREAM_ERROR, "the sign-in service's answer was not understood")
    return TokenGrant(
        access,
        expires,
        refresh if isinstance(refresh, str) and refresh else None,
        scope if isinstance(scope, str) else "",
        id_token if isinstance(id_token, str) else None,
    )


def _post(http: MailboxHttp, provider: Provider, app: AppConfig, form: dict[str, str]) -> Reply:
    form = {"client_id": app.client_id, **form}
    if provider == "gmail" and app.client_secret:
        form["client_secret"] = app.client_secret
    return http.request("POST", token_url(provider, app), data=form, headers={"Accept": "application/json"})


def exchange_code(
    http: MailboxHttp, provider: Provider, app: AppConfig, *, code: str, verifier: str, redirect_uri: str
) -> TokenGrant:
    form = {"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": redirect_uri}
    if provider == "outlook":
        form["scope"] = MICROSOFT_SCOPES
    expired = Rejected(Reason.INVALID_INPUT, "the sign-in expired or was already used; start the connection again")
    grant = _grant(_post(http, provider, app, form), provider, on_invalid_grant=expired)
    granted = set(unquote(grant.scope).lower().split())
    if not granted & REQUIRED_SCOPE[provider] and (provider == "gmail" or granted):
        raise Rejected(
            Reason.INVALID_INPUT,
            "read-only mail access was not granted; connect again and tick the mail permission on the consent screen",
        )
    return grant


def refresh_access(http: MailboxHttp, provider: Provider, app: AppConfig, refresh_token: str) -> TokenGrant:
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if provider == "outlook":
        form["scope"] = MICROSOFT_SCOPES
    return _grant(_post(http, provider, app, form), provider, on_invalid_grant=None)


def revoke_google(http: MailboxHttp, token: str) -> bool:
    """Ask Google to revoke a token. False when the call failed (the caller deletes the local copy anyway)."""
    try:
        reply = http.request(
            "POST", GOOGLE_REVOKE, data={"token": token}, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
    except Rejected:
        return False
    return reply.status == 200
