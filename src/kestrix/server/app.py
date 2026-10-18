"""FastAPI application serving the JSON API and the bundled dashboard.

The server is meant for the user's own machine. Every request passes ``_LocalOnly``:

- the Host header must be a loopback name, which blocks DNS-rebinding attacks;
- state-changing requests from another origin (``Origin`` / ``Sec-Fetch-Site``) are refused,
  which blocks cross-site "simple" POSTs such as multipart uploads;
- request bodies are capped: a declared Content-Length is checked up front and streamed
  (chunked) bodies are counted as they arrive.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
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
from ..forensics.api import router as forensics_router
from ..mail.api import router as mail_router
from ..webcheck.api import router as webcheck_router

STATIC_DIR = Path(str(files("kestrix.server") / "static"))
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY_BYTES = 1024 * 1024
LARGE_BODY_ROUTES = {
    "/api/detect/run": 60 * 1024 * 1024,
    "/api/forensics/file": 51 * 1024 * 1024,
    "/api/mail/analyze": 26 * 1024 * 1024,
}
MODULES = ("detect", "forensics", "webcheck", "bitcoin", "mail")

_STATUS = {
    Reason.INPUT_TOO_LARGE: 413,
    Reason.ENGINE_UNAVAILABLE: 503,
    Reason.AI_KEY_MISSING: 503,
    Reason.UPSTREAM_ERROR: 502,
    Reason.TARGET_UNREACHABLE: 502,
    Reason.TARGET_NOT_ALLOWED: 403,
}

_HTTP_REASONS = {404: "not_found", 405: "method_not_allowed", 413: "input_too_large"}

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _hostname(host_header: str) -> str:
    """Strip the port from a Host header, keeping IPv6 brackets."""
    if host_header.startswith("["):
        return host_header.split("]", 1)[0] + "]"
    return host_header.split(":", 1)[0]


def _refuse(reason: str, detail: str, status: int) -> JSONResponse:
    return JSONResponse({"reason": reason, "detail": detail}, status_code=status, headers=_SECURITY_HEADERS)


class _LocalOnly(BaseHTTPMiddleware):
    def __init__(self, app: object, allowed_hosts: frozenset[str]) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.allowed_hosts = allowed_hosts

    def _cross_site(self, request: Request) -> bool:
        if request.method in SAFE_METHODS:
            return False
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            return True
        origin = request.headers.get("origin")
        return origin is not None and _hostname(urlsplit(origin).netloc) not in self.allowed_hosts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if _hostname(request.headers.get("host", "")) not in self.allowed_hosts:
            return _refuse("host_not_allowed", "Kestrix only serves local requests", 421)
        if self._cross_site(request):
            return _refuse("cross_site_request", "requests from other websites are not allowed", 403)
        declared = request.headers.get("content-length", "0")
        limit = body_limit(request.url.path)
        if not declared.isdigit() or int(declared) > limit:
            return _refuse("input_too_large", f"request body exceeds {limit} bytes", 413)
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response


def body_limit(path: str) -> int:
    return LARGE_BODY_ROUTES.get(path, MAX_BODY_BYTES)


class _StreamedBodyLimit:
    """Counts body bytes as they are received, so chunked uploads without a
    Content-Length cannot exceed the cap either."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit, seen = body_limit(scope["path"]), 0

        async def counted() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, f"request body exceeds {limit} bytes")
            return message

        await self.app(scope, counted, send)


class KeyUpdate(BaseModel):
    key: str | None = Field(default=None, min_length=20, max_length=512)


def create_app(extra_hosts: frozenset[str] = frozenset()) -> FastAPI:
    app = FastAPI(title="Kestrix", version=__version__, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.add_middleware(_StreamedBodyLimit)
    app.add_middleware(_LocalOnly, allowed_hosts=LOOPBACK_HOSTS | extra_hosts)

    @app.exception_handler(HTTPException)
    async def _http_error(_: Request, exc: HTTPException) -> JSONResponse:
        reason = _HTTP_REASONS.get(exc.status_code, "http_error")
        return JSONResponse({"reason": reason, "detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(Rejected)
    async def _rejected(_: Request, exc: Rejected) -> JSONResponse:
        return JSONResponse(
            {"reason": exc.reason.value, "detail": exc.detail}, status_code=_STATUS.get(exc.reason, 400)
        )

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

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        if path.startswith("api/"):
            return JSONResponse({"reason": "not_found", "detail": path}, status_code=404)
        candidate = (STATIC_DIR / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
            return FileResponse(candidate)
        index = STATIC_DIR / "index.html"
        if index.is_file():
            return FileResponse(index)
        return JSONResponse(
            {
                "reason": "dashboard_not_built",
                "detail": "Build it with `npm --prefix frontend run build`; the API schema is at /api/openapi.json",
            },
            status_code=503,
        )

    return app
