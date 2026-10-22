# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application serving the JSON API and the bundled dashboard.

The server is meant for the user's own machine. Every request passes ``_LocalOnly``:

- the Host header must be a loopback name, which blocks DNS-rebinding attacks;
- state-changing requests from another origin (``Origin`` / ``Sec-Fetch-Site``) are refused,
  which blocks cross-site "simple" POSTs such as multipart uploads;
- request bodies are capped: a declared Content-Length is checked up front and streamed
  (chunked) bodies are counted as they arrive;
- an unexpected exception becomes a JSON 500 that still carries the security headers.

With ``KESTRIX_MODE=hosted`` (ADR 0004, ``server/settings.py``) the same middleware allows only
the public origin's host, compares ``Origin`` with the public origin, adds HSTS, marks every
``/api/`` response ``Cache-Control: no-store`` and applies the lower hosted upload caps. Behind it,
``server/hosted.py`` requires sign-in, CSRF tokens, rate limits and concurrency caps; analyses run
in limited worker processes (``server/isolation.py``); detect, bitcoin, the Anthropic-key
settings and the OpenAPI schema are not served.

In both modes ``HistoryRecorder`` (innermost) keeps the report of each successful analysis for 30
days (``server/history.py``, ADR 0008): encrypted per user on the hosted service, in the user's own
config folder locally.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .. import ATTRIBUTION, __version__
from ..bitcoin.api import router as bitcoin_router
from ..core import config
from ..core.errors import Reason, Rejected
from ..detect.api import router as detect_router
from ..forensics.api import hosted_router as hosted_forensics_router
from ..forensics.api import router as forensics_router
from ..mail.api import hosted_router as hosted_mail_router
from ..mail.api import router as mail_router
from ..webcheck.api import hosted_router as hosted_webcheck_router
from ..webcheck.api import router as webcheck_router
from ..webcheck.fetch import user_agent
from .auth import AuthService, current_session
from .auth_api import auth_router
from .headers import IMMUTABLE, NO_STORE, REVALIDATE, SECURITY_HEADERS, hosted_headers
from .history import LOCAL_USER, HistoryCipher, HistoryRecorder, HistoryStore
from .history_api import history_router
from .hosted import AccessLog, HostedGate, site_scan_counter
from .isolation import Isolator, Limits
from .ratelimit import Limiter, RateLimiter, SqliteRateLimiter, rate_limit_path
from .settings import HostedSettings, Settings, load_settings
from .store import Store

STATIC_DIR = Path(str(files("kestrix.server") / "static"))
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY_BYTES = 1024 * 1024
LARGE_BODY_ROUTES = {
    "/api/detect/run": 60 * 1024 * 1024,
    "/api/forensics/file": 51 * 1024 * 1024,
    "/api/mail/analyze": 26 * 1024 * 1024,
}
# Room for the multipart boundary and part headers around a hosted upload.
MULTIPART_OVERHEAD = 64 * 1024
MODULES = ("detect", "forensics", "webcheck", "bitcoin", "mail")
HOSTED_MODULES = ("forensics", "webcheck", "mail")

_STATUS = {
    Reason.INPUT_TOO_LARGE: 413,
    Reason.ENGINE_UNAVAILABLE: 503,
    Reason.AI_KEY_MISSING: 503,
    Reason.UPSTREAM_ERROR: 502,
    Reason.TARGET_UNREACHABLE: 502,
    Reason.TARGET_NOT_ALLOWED: 403,
    Reason.SIGN_IN_REQUIRED: 401,
    Reason.TOKEN_EXPIRED: 401,
    Reason.CSRF_FAILED: 403,
    Reason.REAUTH_REQUIRED: 403,
    Reason.RATE_LIMITED: 429,
    Reason.ANALYSIS_TIMEOUT: 422,
}

_HTTP_REASONS = {404: "not_found", 405: "method_not_allowed", 408: "request_timeout", 413: "input_too_large"}

_SECURITY_HEADERS = SECURITY_HEADERS
_NO_STORE = NO_STORE

log = logging.getLogger("kestrix.server")
webcheck_log = logging.getLogger("kestrix.webcheck")


def _hostname(host_header: str) -> str:
    """Strip the port from a Host header, keeping IPv6 brackets."""
    if host_header.startswith("["):
        return host_header.split("]", 1)[0] + "]"
    return host_header.split(":", 1)[0]


def _refuse(reason: str, detail: str, status: int, headers: dict[str, str] = _SECURITY_HEADERS) -> JSONResponse:
    return JSONResponse({"reason": reason, "detail": detail}, status_code=status, headers=headers)


class _LocalOnly(BaseHTTPMiddleware):
    def __init__(
        self,
        app: object,
        allowed_hosts: frozenset[str],
        public_origin: str | None = None,
        headers: dict[str, str] = _SECURITY_HEADERS,
        body_limits: Mapping[str, int] = LARGE_BODY_ROUTES,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.allowed_hosts = allowed_hosts
        self.public_origin = public_origin  # hosted mode: Origin must equal it exactly
        self.headers = headers
        self.body_limits = body_limits

    def _headers(self, path: str) -> dict[str, str]:
        if self.public_origin is not None and path.startswith("/api/"):
            return {**self.headers, **_NO_STORE}  # hosted API responses are per-user: never cached
        return self.headers

    def _cross_site(self, request: Request) -> bool:
        if request.method in SAFE_METHODS:
            return False
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            return True
        origin = request.headers.get("origin")
        if origin is not None and self.public_origin is not None:
            return origin.lower() != self.public_origin
        return origin is not None and _hostname(urlsplit(origin).netloc) not in self.allowed_hosts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        headers = self._headers(request.url.path)
        if _hostname(request.headers.get("host", "")) not in self.allowed_hosts:
            detail = "Kestrix only serves local requests" if self.public_origin is None else "unknown host"
            return _refuse("host_not_allowed", detail, 421, headers)
        if self._cross_site(request):
            return _refuse("cross_site_request", "requests from other websites are not allowed", 403, headers)
        declared = request.headers.get("content-length", "0")
        limit = body_limit(request.url.path, self.body_limits)
        if not declared.isdigit() or int(declared) > limit:
            return _refuse("input_too_large", f"request body exceeds {limit} bytes", 413, headers)
        try:
            response = await call_next(request)
        except Exception as exc:
            if self.public_origin is None:
                log.exception("unexpected error")  # local: the traceback is the user's own data
            else:  # hosted: the type only; a traceback could quote another person's upload
                log.error("unexpected error %s on %s", type(exc).__name__, request.method)
            response = JSONResponse({"reason": "internal_error", "detail": "unexpected error"}, status_code=500)
        response.headers.update(headers)
        return response


def body_limit(path: str, limits: Mapping[str, int] = LARGE_BODY_ROUTES) -> int:
    return limits.get(path, MAX_BODY_BYTES)


def hosted_body_limits(settings: HostedSettings) -> dict[str, int]:
    """The hosted service's upload caps: the module limit plus room for the multipart framing."""
    return {
        "/api/forensics/file": settings.max_file_bytes + MULTIPART_OVERHEAD,
        "/api/mail/analyze": settings.max_mail_bytes + MULTIPART_OVERHEAD,
    }


class _StreamedBodyLimit:
    """Counts body bytes as they are received, so chunked uploads without a
    Content-Length cannot exceed the cap either.

    With ``idle_s`` set (hosted mode) it also bounds how long a body may take, because uvicorn has no
    read timeout of its own: a pause of more than ``idle_s`` seconds between pieces, or a body still
    arriving after ``total_s`` (``upload_total_s`` for the routes in ``body_limits``) from its first read,
    ends the request with 408 ``request_timeout``. Reads after the body is complete (the disconnect
    watch of a streaming response) are never timed.
    """

    def __init__(
        self,
        app: ASGIApp,
        body_limits: Mapping[str, int] = LARGE_BODY_ROUTES,
        idle_s: float | None = None,
        total_s: float = 30.0,
        upload_total_s: float = 120.0,
    ) -> None:
        self.app = app
        self.body_limits = body_limits
        self.idle_s = idle_s
        self.total_s = total_s
        self.upload_total_s = upload_total_s

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        limit, seen = body_limit(path, self.body_limits), 0
        total = self.upload_total_s if path in self.body_limits else self.total_s
        started: float | None = None
        complete = False

        async def counted() -> Message:
            nonlocal seen, started, complete
            if self.idle_s is None or complete:
                message = await receive()
            else:
                started = time.monotonic() if started is None else started
                remaining = started + total - time.monotonic()
                try:
                    message = await asyncio.wait_for(receive(), max(0.0, min(self.idle_s, remaining)))
                except asyncio.TimeoutError:
                    raise HTTPException(408, "the request body was sent too slowly") from None
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, f"request body exceeds {limit} bytes")
                complete = not message.get("more_body", False)
            return message

        await self.app(scope, counted, send)


class KeyUpdate(BaseModel):
    key: str | None = Field(default=None, min_length=20, max_length=512)


def history_path(db_path: Path) -> Path:
    """The hosted history database, beside the accounts database: ``kestrix.db`` -> ``kestrix-history.db``."""
    return db_path.with_name(f"{db_path.stem}-history{db_path.suffix}")


def _scope_user(scope: Scope) -> int | None:
    """The signed-in user of a hosted request, set by ``HostedGate`` (None: not signed in)."""
    state = scope.get("state")
    session = state.get("session") if isinstance(state, dict) else None
    return getattr(session, "user_id", None)


def _request_user(request: Request) -> int:
    session = current_session(request)
    if session is None:  # the gate already refuses this; kept so the routes are safe on their own
        raise Rejected(Reason.SIGN_IN_REQUIRED, "sign in first")
    return session.user_id


async def _hosted_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """422 without echoing the rejected values: FastAPI's default body repeats each one (``input``, ``ctx``),
    so another person's upload field or a mistyped secret would land in a response and any log of it."""
    problems = [{"type": e["type"], "loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
    return JSONResponse({"detail": jsonable_encoder(problems)}, status_code=422)


def _serve_static(path: str) -> Response:
    """A bundle file, else the dashboard page for a client-side route (``spa`` below)."""
    if path.startswith("api/"):
        return JSONResponse({"reason": "not_found", "detail": path}, status_code=404)
    static = STATIC_DIR.resolve()
    try:
        candidate = (static / path).resolve()
        found = bool(path) and candidate.is_file() and candidate.is_relative_to(static)
    except (OSError, ValueError):  # an embedded NUL or an over-long name is just a path that is not there
        found = False
    if found:
        hashed = candidate.is_relative_to(static / "assets")
        return FileResponse(candidate, headers={"Cache-Control": IMMUTABLE if hashed else REVALIDATE})
    if path.startswith("assets/"):  # a missing bundle file is an error, not the page (it would be cached as a script)
        return JSONResponse({"reason": "not_found", "detail": path}, status_code=404)
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": REVALIDATE})
    return JSONResponse(
        {
            "reason": "dashboard_not_built",
            "detail": "Build it with `npm --prefix frontend run build`; the API schema is at /api/openapi.json",
        },
        status_code=503,
    )


def create_app(
    extra_hosts: frozenset[str] = frozenset(),
    *,
    server_settings: Settings | None = None,
    provider_transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    """Build the app. Settings default to the environment; hosted mode raises ``SettingsError``
    when misconfigured. ``extra_hosts`` applies to local mode only; ``provider_transport``
    replaces the network for sign-in providers in tests."""
    hosted = (load_settings() if server_settings is None else server_settings).hosted
    # The hosted service publishes no API schema: it is a website, not a scripting API.
    openapi_url = "/api/openapi.json" if hosted is None else None
    app = FastAPI(title="Kestrix", version=__version__, docs_url=None, redoc_url=None, openapi_url=openapi_url)
    auth: AuthService | None = None
    limiter: Limiter | None = None
    if hosted is None:
        history = HistoryStore(config.config_dir() / "history.sqlite3")
        app.add_middleware(HistoryRecorder, history=history, user_of=lambda _scope: LOCAL_USER)
        app.add_middleware(_StreamedBodyLimit)
        app.add_middleware(_LocalOnly, allowed_hosts=LOOPBACK_HOSTS | extra_hosts)
    else:
        limits = hosted_body_limits(hosted)
        limiter = (
            SqliteRateLimiter(rate_limit_path(hosted.db_path), hosted.session_pepper)
            if hosted.rate_limit_store == "sqlite"
            else RateLimiter()
        )
        auth = AuthService(hosted, Store(hosted.db_path), transport=provider_transport)
        app.state.auth = auth
        history = HistoryStore(
            history_path(hosted.db_path), HistoryCipher(hosted.history_key, hosted.history_key_previous)
        )
        app.add_middleware(HistoryRecorder, history=history, user_of=_scope_user)
        app.add_middleware(
            _StreamedBodyLimit,
            body_limits=limits,
            idle_s=hosted.body_idle_s,
            total_s=hosted.body_total_s,
            upload_total_s=hosted.upload_total_s,
        )
        app.add_middleware(HostedGate, auth=auth, limiter=limiter)
        app.add_middleware(
            _LocalOnly,
            allowed_hosts=frozenset({hosted.public_host}),
            public_origin=hosted.public_origin,
            headers=hosted_headers(hsts_preload=hosted.hsts_preload),
            body_limits=limits,
        )
        app.add_middleware(AccessLog, auth=auth)

    @app.exception_handler(HTTPException)
    async def _http_error(_: Request, exc: HTTPException) -> JSONResponse:
        reason = _HTTP_REASONS.get(exc.status_code, "http_error")
        return JSONResponse({"reason": reason, "detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(Rejected)
    async def _rejected(_: Request, exc: Rejected) -> JSONResponse:
        return JSONResponse(
            {"reason": exc.reason.value, "detail": exc.detail}, status_code=_STATUS.get(exc.reason, 400)
        )

    if hosted is not None:
        app.add_exception_handler(RequestValidationError, _hosted_validation_error)  # type: ignore[arg-type]

    if auth is None:

        @app.get("/api/health", tags=["platform"])
        def health() -> dict[str, object]:
            return {"status": "ok", "version": __version__, "generated_by": ATTRIBUTION, "modules": list(MODULES)}

        @app.get("/api/settings", tags=["platform"])
        def settings() -> dict[str, bool]:
            return {"anthropic_key_configured": config.anthropic_key() is not None}

        @app.put("/api/settings/anthropic-key", tags=["platform"], status_code=204)
        def set_key(body: KeyUpdate) -> Response:
            config.set_secret("anthropic_api_key", body.key)
            return Response(status_code=204)

        for router in (detect_router, forensics_router, webcheck_router, bitcoin_router, mail_router):
            app.include_router(router)
        app.include_router(history_router(history, lambda _request: LOCAL_USER))
    else:
        assert hosted is not None and limiter is not None
        isolator = Isolator(Limits(hosted.analysis_cpu_s, hosted.analysis_memory_bytes, hosted.analysis_wall_s))
        isolator.start()
        hosted_auth = auth

        def audit_webcheck(request: Request, url: str) -> None:
            """One line per hosted website check: who (salted user hash) and a keyed hash of the host,
            so an abuse report about a host can be matched (``kestrix hosted hash-host``)."""
            session = current_session(request)
            webcheck_log.info(
                "webcheck user=%s host=%s",
                hosted_auth.user_tag(session.user_id) if session is not None else "-",
                hosted_auth.host_tag(url),
            )

        @app.get("/api/health", tags=["platform"])
        def hosted_health() -> dict[str, object]:
            return {
                "status": "ok",
                "version": __version__,
                "generated_by": ATTRIBUTION,
                "mode": "hosted",
                "modules": list(HOSTED_MODULES),
            }

        for router in (
            hosted_forensics_router(isolator, hosted.max_file_bytes),
            hosted_webcheck_router(user_agent(hosted.abuse_contact), audit_webcheck, site_scan_counter(limiter)),
            hosted_mail_router(isolator, hosted.max_mail_bytes),
            auth_router(auth, limiter, history),
            history_router(history, _request_user),
        ):
            app.include_router(router)

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        return _serve_static(path)

    app.state.history = history
    return app
