# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP routes for hosted-mode sign-in, token refresh, sign-out and account deletion (``/api/auth``).

Thin adapters over :class:`kestrix.server.auth.AuthService`. The access token is verified by the
hosted gate middleware, which also enforces the CSRF header on state-changing requests that carry
one; refresh and logout check the CSRF token against the refresh family themselves, because the
access token may have expired. A failed sign-in always redirects to the same page with no detail;
only a fixed reason code is logged.
"""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from ..core.errors import Reason, Rejected
from .auth import (
    ACCESS_COOKIE,
    FAILED_REDIRECT,
    LOGIN_COOKIE,
    LOGIN_TTL_S,
    PROVIDERS,
    REFRESH_COOKIE,
    AuthFailed,
    AuthService,
    Tokens,
    current_session,
)
from .history import HistoryStore
from .hosted import user_limit_keys
from .ratelimit import Limiter

log = logging.getLogger("kestrix.auth")
_NO_STORE = {"Cache-Control": "no-store"}

SameSite = Literal["lax", "strict"]


def _set_cookie(response: Response, name: str, value: str, max_age: int, samesite: SameSite = "lax") -> None:
    # A __Host- cookie must be Secure, have Path=/ and no Domain, so it is bound to this exact host.
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite=samesite)


def _clear_cookie(response: Response, name: str, samesite: SameSite = "lax") -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite=samesite)


def _set_tokens(response: Response, tokens: Tokens) -> None:
    _set_cookie(response, ACCESS_COOKIE, tokens.access_token, tokens.access_max_age)
    _set_cookie(response, REFRESH_COOKIE, tokens.refresh_token, tokens.refresh_max_age, "strict")


def _clear_tokens(response: Response) -> None:
    _clear_cookie(response, ACCESS_COOKIE)
    _clear_cookie(response, REFRESH_COOKIE, "strict")


def auth_router(auth: AuthService, limiter: Limiter, history: HistoryStore) -> APIRouter:  # noqa: PLR0915 - one statement list per route
    router = APIRouter(prefix="/api/auth", tags=["auth"])

    @router.get("/providers")
    def providers() -> dict[str, list[str]]:
        """Sign-in providers enabled on this server."""
        return {"providers": auth.providers}

    @router.get("/login/{provider}", response_class=RedirectResponse, status_code=302)
    def login(provider: str, request: Request) -> Response:
        """Start sign-in: redirect to the provider. ``next`` must be a same-origin path such as ``/app``;
        ``intent=signup`` comes from the Sign up tab, after the visitor agreed to the terms."""
        if provider not in auth.providers:
            raise HTTPException(404, "unknown sign-in provider")
        intent: Literal["login", "signup"] = "signup" if request.query_params.get("intent") == "signup" else "login"
        start = auth.start_login(provider, request.query_params.get("next"), intent)
        response = RedirectResponse(start.redirect_url, status_code=302, headers=_NO_STORE)
        _set_cookie(response, LOGIN_COOKIE, start.state, LOGIN_TTL_S)
        return response

    @router.get("/callback/{provider}", response_class=RedirectResponse, status_code=303)
    def callback(provider: str, request: Request) -> Response:
        """Finish sign-in, set the access and refresh cookies and redirect to ``next`` (default ``/app``)."""
        query = request.query_params
        try:
            signin = auth.finish_login(
                provider,
                state=query.get("state"),
                code=query.get("code"),
                error=query.get("error"),
                bound_state=request.cookies.get(LOGIN_COOKIE),
                previous_refresh_token=request.cookies.get(REFRESH_COOKIE),
            )
        except AuthFailed as exc:
            log.warning("sign-in failed provider=%s reason=%s", provider if provider in PROVIDERS else "-", exc.code)
            response = RedirectResponse(FAILED_REDIRECT, status_code=303, headers=_NO_STORE)
            _clear_cookie(response, LOGIN_COOKIE)
            return response
        response = RedirectResponse(signin.next, status_code=303, headers=_NO_STORE)
        _clear_cookie(response, LOGIN_COOKIE)
        _set_tokens(response, signin.tokens)
        return response

    @router.get("/me")
    def me(request: Request, response: Response) -> dict[str, object]:
        """Who is signed in, the CSRF token to send as ``X-CSRF-Token``, and when the access token expires.
        Without a usable access token but with a live refresh family: ``refreshable`` and the CSRF token."""
        response.headers.update(_NO_STORE)
        session = current_session(request)
        if session is None:
            family = auth.refreshable(request.cookies.get(REFRESH_COOKIE))
            if family is None:
                return {"signed_in": False}
            return {"signed_in": False, "refreshable": True, "csrf_token": auth.csrf_token(family.sid)}
        return {
            "signed_in": True,
            "user": {"display_name": session.display_name, "email": session.email, "provider": session.provider},
            "csrf_token": session.csrf_token,
            "access_expires_at": session.access_expires_at,
        }

    @router.post("/refresh")
    def refresh(request: Request) -> Response:
        """Rotate the refresh token and issue a new access token. Requires ``X-CSRF-Token``."""
        try:
            tokens = auth.refresh(
                request.cookies.get(REFRESH_COOKIE),
                request.headers.get("x-csrf-token"),
                request.headers.get("user-agent"),
            )
        except AuthFailed as exc:
            if exc.code == "csrf_failed":
                raise Rejected(Reason.CSRF_FAILED, "missing or invalid X-CSRF-Token header") from None
            log.info("refresh refused reason=%s", exc.code)
            response = JSONResponse(
                {"reason": Reason.SIGN_IN_REQUIRED.value, "detail": "sign in again"}, status_code=401, headers=_NO_STORE
            )
            _clear_tokens(response)
            return response
        response = JSONResponse({"access_expires_at": tokens.access_expires_at}, headers=_NO_STORE)
        _set_tokens(response, tokens)
        return response

    @router.post("/logout", status_code=204)
    def logout(request: Request) -> Response:
        """End this sign-in (its refresh family). Requires ``X-CSRF-Token`` when there is one to end."""
        if not auth.logout(
            current_session(request), request.cookies.get(REFRESH_COOKIE), request.headers.get("x-csrf-token")
        ):
            raise Rejected(Reason.CSRF_FAILED, "missing or invalid X-CSRF-Token header")
        response = Response(status_code=204)
        _clear_tokens(response)
        return response

    @router.delete("/account", status_code=204)
    def delete_account(request: Request) -> Response:
        """Delete the signed-in user, every refresh family of that user, their result history and their
        rate-limit counters. Requires ``X-CSRF-Token`` and a sign-in at most ``reauth_window_s`` old
        (403 ``reauth_required`` otherwise; nothing is deleted)."""
        session = current_session(request)
        if session is None:  # the gate already refuses this; kept so the route is safe on its own
            raise Rejected(Reason.SIGN_IN_REQUIRED, "sign in first")
        if not auth.recently_signed_in(session):
            minutes = max(1, auth.settings.reauth_window_s // 60)
            raise Rejected(
                Reason.REAUTH_REQUIRED,
                "sign in again to confirm; deleting an account needs a sign-in from the last "
                f"{minutes} minute{'s' if minutes != 1 else ''}",
            )
        history.forget_user(session.user_id)
        auth.delete_account(session)
        limiter.forget(user_limit_keys(session.user_id))
        response = Response(status_code=204)
        _clear_tokens(response)
        return response

    return router
