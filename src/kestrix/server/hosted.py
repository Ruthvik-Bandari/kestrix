# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode middleware: sign-in gate, CSRF, rate limits and privacy-safe access logs.

``HostedGate`` runs after the Host / Origin checks and decides, per request:

1. routes of modules that stay local-only (detect, bitcoin, Anthropic-key settings) are 404; the
   result-history setting (``/api/settings/history``) is served;
2. a sign-in start from another site is refused (403) unless it is a top-level navigation,
   so a page cannot burn a visitor's sign-in allowance with hidden requests;
3. sign-in and token-refresh routes are rate-limited per client IP (IPv6 per /64);
4. the access token is verified and its refresh family checked (``request.state.session``,
   ADR 0007);
5. every ``/api/`` route that is not explicitly public needs a session: 401 ``token_expired`` when
   the client should refresh, else 401 ``sign_in_required``, so a new route is private by default;
6. a state-changing request with a session needs a matching ``X-CSRF-Token`` (403); the public
   refresh and logout routes check it themselves against the refresh family;
7. module work runs one request at a time per user (429 ``busy``), within global caps on
   concurrent analyses and website checks (503 ``busy``), and is rate-limited per user (429
   ``rate_limited``). All three answer at once with ``Retry-After``; nothing waits in a queue or
   holds a worker thread.
8. result-history writes (``/api/history``, ``/api/settings/history``) are rate-limited per user.

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
from .auth import ACCESS_COOKIE, REFRESH_COOKIE, AuthService, Session, current_session
from .ratelimit import RateLimiter, client_ip, ip_key

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOCAL_ONLY_PREFIXES = ("/api/detect", "/api/bitcoin", "/api/settings")
HOSTED_SETTINGS = frozenset({"/api/settings/history"})
HISTORY_WRITE_PREFIXES = ("/api/history", "/api/settings/history")
PUBLIC_API = frozenset({"/api/health", "/api/auth/providers", "/api/auth/me", "/api/auth/logout", "/api/auth/refresh"})
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
    "/api/auth/login/": ("login", 20, TEN_MINUTES),
    "/api/auth/callback/": ("callback", 10, TEN_MINUTES),
    "/api/auth/refresh": ("refresh", 60, TEN_MINUTES),
}
# Per signed-in user, for every state-changing history request.
HISTORY_LIMIT = ("history", 120, HOUR)
LOGIN_PREFIX = "/api/auth/login/"
BUSY_RETRY_S = 5

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


def _busy(status: int, detail: str) -> JSONResponse:
    return _deny(Reason.BUSY, detail, status, {"Retry-After": str(BUSY_RETRY_S)})


def user_limit_keys(user_id: int) -> set[str]:
    """Every per-user rate-limit key of this user (cleared when the account is deleted)."""
    return {f"{bucket}:{user_id}" for bucket, _, _ in (*USER_LIMITS.values(), HISTORY_LIMIT)}


def _hidden_cross_site(request: Request) -> bool:
    """A cross-site request that is not a top-level navigation (an image, script or fetch)."""
    headers = request.headers
    return headers.get("sec-fetch-site") == "cross-site" and not (
        headers.get("sec-fetch-mode") == "navigate" and headers.get("sec-fetch-dest") == "document"
    )


class HostedGate(BaseHTTPMiddleware):
    def __init__(self, app: object, auth: AuthService, limiter: RateLimiter) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.auth = auth
        self.limiter = limiter
        self.caps = {
            "analysis": auth.settings.max_concurrent_analyses,
            "webcheck": auth.settings.max_concurrent_webchecks,
        }
        # Only touched on the event loop, between awaits, so no lock is needed.
        self._running = dict.fromkeys(self.caps, 0)
        self._busy_users: set[int] = set()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path, method = request.url.path, request.method
        if _under(path, LOCAL_ONLY_PREFIXES) and path not in HOSTED_SETTINGS:
            return _deny("not_found", "this route is not available on the hosted service", 404)
        if path.startswith(LOGIN_PREFIX) and _hidden_cross_site(request):
            return _deny("cross_site_request", "sign-in must be started from a link, not loaded by another site", 403)
        for prefix, (bucket, limit, window) in IP_LIMITS.items():
            if path.startswith(prefix):
                ip = client_ip(
                    request,
                    trust_proxy_headers=self.auth.settings.trust_proxy_headers,
                    client_ip_header=self.auth.settings.client_ip_header,
                )
                retry = self.limiter.hit(f"{bucket}:{ip_key(ip)}", limit, window)
                if retry is not None:
                    return _rate_limited(retry)
        public = not path.startswith("/api/") or path in PUBLIC_API or path.startswith(PUBLIC_API_PREFIXES)
        if not path.startswith("/api/"):
            return await call_next(request)  # the dashboard's files need no session
        checked = await run_in_threadpool(
            lambda: self.auth.authenticate(
                request.cookies.get(ACCESS_COOKIE), has_refresh=bool(request.cookies.get(REFRESH_COOKIE))
            )
        )
        session = checked if isinstance(checked, Session) else None
        request.state.session = session
        if session is None and not public:
            if checked == "token_expired":
                return _deny(Reason.TOKEN_EXPIRED, "your sign-in needs refreshing; call POST /api/auth/refresh", 401)
            return _deny(Reason.SIGN_IN_REQUIRED, "sign in to use this feature", 401)
        if method not in SAFE_METHODS and session is not None:
            if not self.auth.csrf_ok(session.csrf_token, request.headers.get("x-csrf-token")):
                return _deny(Reason.CSRF_FAILED, "missing or invalid X-CSRF-Token header", 403)
            if _under(path, HISTORY_WRITE_PREFIXES):
                bucket, limit, window = HISTORY_LIMIT
                retry = self.limiter.hit(f"{bucket}:{session.user_id}", limit, window)
                if retry is not None:
                    return _rate_limited(retry)
            rule = USER_LIMITS.get(path)
            if rule is not None and method == "POST":
                return await self._module_work(request, call_next, session.user_id, rule)
        return await call_next(request)

    async def _module_work(
        self, request: Request, call_next: RequestResponseEndpoint, user_id: int, rule: tuple[str, int, int]
    ) -> Response:
        bucket, limit, window = rule
        if user_id in self._busy_users:
            return _busy(429, "your previous check is still running; try again when it finishes")
        if self._running[bucket] >= self.caps[bucket]:
            return _busy(503, "the service is busy; try again in a few seconds")
        retry = self.limiter.hit(f"{bucket}:{user_id}", limit, window)
        if retry is not None:
            return _rate_limited(retry)
        self._busy_users.add(user_id)
        self._running[bucket] += 1
        try:
            return await call_next(request)
        finally:
            self._busy_users.discard(user_id)
            self._running[bucket] -= 1


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
