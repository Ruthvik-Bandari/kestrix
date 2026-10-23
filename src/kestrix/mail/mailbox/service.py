# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The mailbox connector: connect, search, check one message, disconnect (ADR 0009).

One instance per local server. Pending sign-ins and access tokens live in memory only. The refresh token
is the only credential stored (`store.py`). Nothing here logs a message list, a message id, a query, a
code or a token.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

import httpx

from ...core.errors import Reason, Rejected
from ...core.netguard import check_url
from ..analyze import analyze
from ..models import MailReport
from . import oauth, providers, store
from .http import MailboxHttp, UrlCheck
from .models import (
    MAX_PAGE_SIZE,
    MAX_QUERY_CHARS,
    DisconnectResult,
    Folder,
    MailboxStatus,
    Provider,
    ProviderStatus,
    SearchParams,
    SearchResult,
    StartResult,
)

log = logging.getLogger("kestrix.mailbox")
_T = TypeVar("_T")

FLOW_TTL_S = 600
MAX_PENDING_FLOWS = 8
EXPIRY_MARGIN_S = 60
CALLBACK_PATH = "/mail/connect"
LABELS = {"gmail": "Gmail", "outlook": "Outlook / Microsoft 365"}
SCOPES = {"gmail": providers.GMAIL_SCOPE, "outlook": providers.GRAPH_SCOPE}
HOSTS = {
    "gmail": ["accounts.google.com", "oauth2.googleapis.com", "gmail.googleapis.com"],
    "outlook": ["login.microsoftonline.com", "graph.microsoft.com"],
}
REGISTER_URI = {"gmail": None, "outlook": f"http://localhost{CALLBACK_PATH}"}
REVOKE_HELP = {
    "gmail": "revoke it at https://myaccount.google.com/permissions",
    "outlook": (
        "remove the app at https://myapps.microsoft.com (work or school account) or "
        "https://account.live.com/consent/Manage (personal account)"
    ),
}


@dataclass
class _Flow:
    provider: Provider
    verifier: str
    redirect_uri: str
    binding: str | None
    created: float


class MailboxService:
    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        check: UrlCheck = check_url,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._http = MailboxHttp(transport, check)
        self._clock = clock
        self._lock = threading.Lock()
        self._flows: dict[str, _Flow] = {}
        self._access: dict[Provider, tuple[str, float]] = {}

    # Settings and status

    def status(self) -> MailboxStatus:
        return MailboxStatus(providers=[self._provider_status(p) for p in store.PROVIDERS])

    def _provider_status(self, provider: Provider) -> ProviderStatus:
        connected = store.refresh_token(provider) is not None
        return ProviderStatus(
            provider=provider,
            label=LABELS[provider],
            configured=store.load_app(provider) is not None,
            connected=connected,
            account=store.account(provider) if connected else None,
            scope=SCOPES[provider],
            hosts=HOSTS[provider],
            register_redirect_uri=REGISTER_URI[provider],
        )

    def configure(
        self, provider: Provider, client_id: str, client_secret: str | None, tenant: str | None
    ) -> ProviderStatus:
        app = store.validate_app(provider, client_id, client_secret, tenant)
        if store.refresh_token(provider) is not None:
            raise Rejected(Reason.INVALID_INPUT, "disconnect this mailbox before changing its app settings")
        store.save_app(provider, app)
        return self._provider_status(provider)

    # Sign-in

    def start(self, provider: Provider, redirect_uri: str, *, acknowledged: bool, binding: str | None) -> StartResult:
        if not acknowledged:
            raise Rejected(Reason.INVALID_INPUT, "confirm that Kestrix may contact the provider (acknowledge_network)")
        app = store.load_app(provider)
        if app is None:
            raise Rejected(Reason.MAILBOX_NOT_CONFIGURED, f"enter your {LABELS[provider]} app's client ID first")
        verifier, challenge = oauth.pkce_pair()
        state = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._flows = {k: f for k, f in self._flows.items() if now - f.created < FLOW_TTL_S}
            while len(self._flows) >= MAX_PENDING_FLOWS:
                self._flows.pop(next(iter(self._flows)))
            self._flows[state] = _Flow(provider, verifier, redirect_uri, binding, now)
        return StartResult(
            authorize_url=oauth.authorize_url(provider, app, redirect_uri, state, challenge), expires_in=FLOW_TTL_S
        )

    def _take_flow(self, state: str, binding: str | None) -> _Flow:
        with self._lock:
            flow = self._flows.pop(state, None)  # single use: gone before anything else happens
        if flow is None or self._clock() - flow.created >= FLOW_TTL_S:
            raise Rejected(Reason.INVALID_INPUT, "this sign-in is unknown or expired; start the connection again")
        if (flow.binding is None) != (binding is None) or (
            flow.binding is not None and binding is not None and not hmac.compare_digest(flow.binding, binding)
        ):
            raise Rejected(Reason.INVALID_INPUT, "this sign-in was not started in this browser; start it again here")
        return flow

    def cancel(self, state: str, binding: str | None) -> None:
        """The user refused or the provider reported an error: drop the pending sign-in."""
        try:
            self._take_flow(state, binding)
        except Rejected:
            return

    def complete(self, state: str, code: str, binding: str | None) -> ProviderStatus:
        flow = self._take_flow(state, binding)
        provider = flow.provider
        app = store.load_app(provider)
        if app is None:
            raise Rejected(Reason.MAILBOX_NOT_CONFIGURED, "the app settings were removed; enter them again")
        grant = oauth.exchange_code(
            self._http, provider, app, code=code, verifier=flow.verifier, redirect_uri=flow.redirect_uri
        )
        if grant.refresh_token is None:
            raise Rejected(
                Reason.UPSTREAM_ERROR,
                f"no refresh token was issued; {REVOKE_HELP[provider]} and connect again",
            )
        label = providers.id_token_label(grant.id_token)
        if provider == "gmail":
            try:
                label = providers.API[provider].account_label(self._http, grant.access_token)
            except (Rejected, providers.Unauthorized):
                label = None
        store.save_refresh_token(provider, grant.refresh_token)
        store.save_account(provider, label)
        self._remember(provider, grant)
        log.info("mailbox connected provider=%s", provider)
        return self._provider_status(provider)

    # Tokens

    def _remember(self, provider: Provider, grant: oauth.TokenGrant) -> None:
        with self._lock:
            self._access[provider] = (grant.access_token, self._clock() + grant.expires_in)

    def _access_token(self, provider: Provider, *, force: bool = False) -> str:
        app = store.load_app(provider)
        if app is None:
            raise Rejected(Reason.MAILBOX_NOT_CONFIGURED, f"enter your {LABELS[provider]} app's client ID first")
        stored = store.refresh_token(provider)
        if stored is None:
            raise Rejected(Reason.MAILBOX_NOT_CONNECTED, f"{LABELS[provider]} is not connected")
        with self._lock:
            cached = self._access.get(provider)
            if cached and not force and cached[1] - EXPIRY_MARGIN_S > self._clock():
                return cached[0]
        try:
            grant = oauth.refresh_access(self._http, provider, app, stored)
        except oauth.ReconnectRequired:
            self._forget(provider)
            raise Rejected(
                Reason.MAILBOX_RECONNECT_REQUIRED,
                f"{LABELS[provider]} no longer accepts the saved sign-in (revoked, expired or password changed); connect again",
            ) from None
        if grant.refresh_token and grant.refresh_token != stored:  # Microsoft rotates refresh tokens
            store.save_refresh_token(provider, grant.refresh_token)
        self._remember(provider, grant)
        return grant.access_token

    def _forget(self, provider: Provider) -> None:
        with self._lock:
            self._access.pop(provider, None)
        store.clear_tokens(provider)

    def _call(self, provider: Provider, action: Callable[[str], _T]) -> _T:
        for attempt in (0, 1):
            token = self._access_token(provider, force=attempt == 1)
            try:
                return action(token)
            except providers.Unauthorized:
                with self._lock:
                    self._access.pop(provider, None)
        raise Rejected(
            Reason.MAILBOX_RECONNECT_REQUIRED,
            f"{LABELS[provider]} refused the saved sign-in; connect again",
        )

    # Use

    def search(
        self, provider: Provider, query: str, folder: Folder, page_token: str | None, limit: int
    ) -> SearchResult:
        query = " ".join(query.split())
        if len(query) > MAX_QUERY_CHARS or not 1 <= limit <= MAX_PAGE_SIZE:
            raise Rejected(Reason.INVALID_INPUT, "query or page size is out of range")
        api = providers.API[provider]
        result = self._call(
            provider,
            lambda token: api.search(
                self._http, token, SearchParams(query=query, folder=folder, page_token=page_token, limit=limit)
            ),
        )
        log.info("mailbox search provider=%s rows=%d", provider, len(result.messages))
        return result

    def check(
        self,
        provider: Provider,
        message_id: str,
        *,
        protected_domains: frozenset[str] = frozenset(),
        trusted_authserv_ids: frozenset[str] = frozenset(),
    ) -> MailReport:
        api = providers.API[provider]
        raw = self._call(provider, lambda token: api.fetch_raw(self._http, token, message_id))
        report = analyze(raw, protected_domains=protected_domains, trusted_authserv_ids=trusted_authserv_ids)
        log.info("mailbox check provider=%s verdict=%s", provider, report.verdict)
        return report

    # Disconnect

    def disconnect(self, provider: Provider, *, forget_app: bool = False) -> DisconnectResult:
        token = store.refresh_token(provider)
        revoked: bool | None = None
        if provider == "gmail":
            revoked = oauth.revoke_google(self._http, token) if token else None
            detail = (
                "Google confirmed the revoke and the saved sign-in is deleted."
                if revoked
                else f"The saved sign-in is deleted here. Google was not reached or did not confirm; {REVOKE_HELP[provider]}."
            )
        else:
            detail = (
                "The saved sign-in is deleted here. Microsoft has no revoke call for this sign-in, so to remove "
                f"Kestrix's access completely, {REVOKE_HELP[provider]}."
            )
        self._forget(provider)
        with self._lock:
            self._flows = {k: f for k, f in self._flows.items() if f.provider != provider}
        if forget_app:
            store.clear_app(provider)
        log.info("mailbox disconnected provider=%s", provider)
        return DisconnectResult(provider=provider, revoked=revoked, detail=detail)
