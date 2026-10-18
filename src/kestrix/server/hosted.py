# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode middleware: sign-in gate, CSRF, rate limits and privacy-safe access logs.

``HostedGate`` runs after the Host / Origin checks and decides, per request:

1. routes of modules that stay local-only (detect, bitcoin, Anthropic-key settings) are 404;
2. sign-in routes are rate-limited per client IP;
3. the session cookie is resolved (``request.state.session``);
4. every ``/api/`` route that is not explicitly public needs a session (401), so a new route
   is private by default;
5. a state-changing request with a session needs a matching ``X-CSRF-Token`` (403);
6. module work is rate-limited per user (429 with ``Retry-After``).

``AccessLog`` writes one line per request with the method, the route template (never the
query string), the status, the duration and a salted hash of the user id. It never sees
bodies, file names, emails, cookies or tokens.
"""

from __future__ import annotations

import logging
import time

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ..core.errors import Reason
from .auth import SESSION_COOKIE, AuthService, current_session
from .ratelimit import RateLimiter, client_ip

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOCAL_ONLY_PREFIXES = ("/api/detect", "/api/bitcoin", "/api/settings")
PUBLIC_API = frozenset({"/api/health", "/api/openapi.json", "/api/auth/providers", "/api/auth/me", "/api/auth/logout"})
PUBLIC_API_PREFIXES = ("/api/auth/login/", "/api/auth/callback/")
HOUR, TEN_MINUTES = 3600, 600
# path -> (bucket, limit, window seconds), counted per signed-in user for POST requests
USER_LIMITS = {
    "/api/webcheck": ("webcheck", 20, HOUR),
    "/api/forensics/file": ("analysis", 120, HOUR),
    "/api/forensics/url": ("analysis", 120, HOUR),
    "/api/mail/analyze": ("analysis", 120, HOUR),
}
# path prefix -> (bucket, limit, window seconds), counted per client IP
IP_LIMITS = {
    "/api/auth/login/": ("login", 10, TEN_MINUTES),
    "/api/auth/callback/": ("callback", 10, TEN_MINUTES),
}

access_log = logging.getLogger("kestrix.access")


def _under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def _deny(reason: Reason | str, detail: str, status: int, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"reason": str(reason), "detail": detail}, status_code=status, headers=headers)


def _rate_limited(retry_after: int) -> JSONResponse:
    return _deny(
        Reason.RATE_LIMITED,
        f"too many requests; try again in {retry_after} seconds",
        429,
        {"Retry-After": str(retry_after)},
    )


class HostedGate(BaseHTTPMiddleware):
    def __init__(self, app: object, auth: AuthService, limiter: RateLimiter) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.auth = auth
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path, method = request.url.path, request.method
        if _under(path, LOCAL_ONLY_PREFIXES):
            return _deny("not_found", "this route is not available on the hosted service", 404)
        for prefix, (bucket, limit, window) in IP_LIMITS.items():
            if path.startswith(prefix):
                ip = client_ip(request, trust_proxy_headers=self.auth.settings.trust_proxy_headers)
                retry = self.limiter.hit(f"{bucket}:{ip}", limit, window)
                if retry is not None:
                    return _rate_limited(retry)
        request.state.session = await run_in_threadpool(
            self.auth.session_from_cookie, request.cookies.get(SESSION_COOKIE)
        )
        session = current_session(request)
        public = not path.startswith("/api/") or path in PUBLIC_API or path.startswith(PUBLIC_API_PREFIXES)
        if session is None and not public:
            return _deny(Reason.SIGN_IN_REQUIRED, "sign in to use this feature", 401)
        if method not in SAFE_METHODS and session is not None:
            if not self.auth.csrf_ok(session, request.headers.get("x-csrf-token")):
                return _deny(Reason.CSRF_FAILED, "missing or invalid X-CSRF-Token header", 403)
            rule = USER_LIMITS.get(path)
            if rule is not None and method == "POST":
                bucket, limit, window = rule
                retry = self.limiter.hit(f"{bucket}:{session.user_id}", limit, window)
                if retry is not None:
                    return _rate_limited(retry)
        return await call_next(request)


def _printable(path: str) -> str:
    return "".join(ch if ch.isprintable() and ch != " " else "?" for ch in path[:200])


class AccessLog(BaseHTTPMiddleware):
    def __init__(self, app: object, auth: AuthService) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.auth = auth

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = getattr(request.scope.get("route"), "path", None)
            session = current_session(request)
            access_log.info(
                "%s %s %d %dms user=%s",
                request.method,
                route if isinstance(route, str) else _printable(request.url.path),
                status,
                round((time.perf_counter() - started) * 1000),
                self.auth.user_tag(session.user_id) if session is not None else "-",
            )
