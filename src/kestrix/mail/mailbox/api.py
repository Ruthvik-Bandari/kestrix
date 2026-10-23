# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Local-mode routes of the mailbox connector (ADR 0009). The hosted service never registers them.

Every outbound call is a `POST` (so the local cross-site and Host protections apply and `GET` routes keep
no side effects). The sign-in's browser binding is an HttpOnly, SameSite=Strict cookie scoped to these routes.
"""

from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Request, Response
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from ...core.errors import Reason, Rejected
from ..analyze import validate_authserv_ids, validate_protected_domains
from ..models import MailReport
from .models import (
    MAX_PAGE_SIZE,
    MAX_QUERY_CHARS,
    DisconnectResult,
    Folder,
    MailboxStatus,
    Provider,
    ProviderStatus,
    SearchResult,
    StartResult,
    Strict,
)
from .service import CALLBACK_PATH, FLOW_TTL_S, MailboxService

PREFIX = "/api/mail/mailbox"
BINDING_COOKIE = "kx_mailbox_flow"
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost"})
_ERROR_CODE = re.compile(r"[a-z_]{1,64}")


class ConfigBody(Strict):
    client_id: str = Field(min_length=1, max_length=200)
    client_secret: str | None = Field(default=None, max_length=256)
    tenant: str | None = Field(default=None, max_length=128)


class StartBody(Strict):
    acknowledge_network: bool = False


class CallbackBody(Strict):
    state: str = Field(min_length=1, max_length=256)
    code: str | None = Field(default=None, max_length=4096)
    error: str | None = Field(default=None, max_length=200)


class SearchBody(Strict):
    query: str = Field(default="", max_length=MAX_QUERY_CHARS)
    folder: Folder = "inbox"
    page_token: str | None = Field(default=None, max_length=2048)
    limit: int = Field(default=20, ge=1, le=MAX_PAGE_SIZE)


class CheckBody(Strict):
    message_id: str = Field(min_length=1, max_length=512)
    protected_domains: list[str] = Field(default_factory=list, max_length=20)
    trusted_authserv_id: str | None = Field(default=None, max_length=253)


def redirect_uri_for(request: Request, provider: Provider) -> str:
    """``http://<host>:<port>/mail/connect``, with the host and port the dashboard was opened with."""
    host, port = request.url.hostname, request.url.port
    if host not in LOOPBACK_NAMES:
        raise Rejected(
            Reason.INVALID_INPUT,
            "open the dashboard at http://127.0.0.1:8765 or http://localhost:8765 to connect a mailbox",
        )
    if provider == "outlook" and host != "localhost":
        raise Rejected(
            Reason.INVALID_INPUT,
            "Microsoft accepts http://localhost as the redirect address; open the dashboard at "
            f"http://localhost{f':{port}' if port else ''}/mail and connect again",
        )
    return f"http://{host}{f':{port}' if port else ''}{CALLBACK_PATH}"


def mailbox_router(service: MailboxService) -> APIRouter:
    router = APIRouter(prefix=PREFIX, tags=["mailbox"])

    @router.get("/status")
    def status() -> MailboxStatus:
        return service.status()

    @router.put("/{provider}/config")
    def configure(provider: Provider, body: ConfigBody) -> ProviderStatus:
        return service.configure(provider, body.client_id, body.client_secret, body.tenant)

    @router.post("/{provider}/start")
    def start(provider: Provider, body: StartBody, request: Request, response: Response) -> StartResult:
        binding = secrets.token_urlsafe(32)
        result = service.start(
            provider, redirect_uri_for(request, provider), acknowledged=body.acknowledge_network, binding=binding
        )
        response.set_cookie(BINDING_COOKIE, binding, max_age=FLOW_TTL_S, httponly=True, samesite="strict", path=PREFIX)
        return result

    @router.post("/callback")
    async def callback(body: CallbackBody, request: Request, response: Response) -> ProviderStatus:
        binding = request.cookies.get(BINDING_COOKIE)
        response.delete_cookie(BINDING_COOKIE, path=PREFIX)
        if body.error is not None or not body.code:
            service.cancel(body.state, binding)
            code = body.error if body.error and _ERROR_CODE.fullmatch(body.error) else "unknown"
            raise Rejected(Reason.INVALID_INPUT, f"sign-in was not completed ({code}); no mailbox was connected")
        return await run_in_threadpool(service.complete, body.state, body.code, binding)

    @router.post("/{provider}/search")
    async def search(provider: Provider, body: SearchBody) -> SearchResult:
        return await run_in_threadpool(service.search, provider, body.query, body.folder, body.page_token, body.limit)

    @router.post("/{provider}/check")
    async def check(provider: Provider, body: CheckBody) -> MailReport:
        return await run_in_threadpool(
            lambda: service.check(
                provider,
                body.message_id,
                protected_domains=validate_protected_domains(frozenset(body.protected_domains)),
                trusted_authserv_ids=validate_authserv_ids(
                    frozenset([body.trusted_authserv_id] if body.trusted_authserv_id else [])
                ),
            )
        )

    @router.delete("/{provider}")
    async def disconnect(provider: Provider, forget_app: bool = False) -> DisconnectResult:
        return await run_in_threadpool(lambda: service.disconnect(provider, forget_app=forget_app))

    return router
