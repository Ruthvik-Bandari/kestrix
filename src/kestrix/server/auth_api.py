# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP routes for hosted-mode sign-in, sign-out and account deletion (``/api/auth``).

Thin adapters over :class:`kestrix.server.auth.AuthService`. The session itself is looked up
by the hosted gate middleware, which also enforces the CSRF header on state-changing requests.
A failed sign-in always redirects to the same page with no detail; only a fixed reason code
is logged.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response
from starlette.exceptions import HTTPException

from ..core.errors import Reason, Rejected
from .auth import (
    FAILED_REDIRECT,
    LOGIN_COOKIE,
    LOGIN_TTL_S,
    PROVIDERS,
    SESSION_ABSOLUTE_S,
    SESSION_COOKIE,
    AuthFailed,
    AuthService,
    current_session,
)

log = logging.getLogger("kestrix.auth")
_NO_STORE = {"Cache-Control": "no-store"}


def _set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    # A __Host- cookie must be Secure, have Path=/ and no Domain, so it is bound to this exact host.
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax")


def _clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="lax")


def auth_router(auth: AuthService) -> APIRouter:
    router = APIRouter(prefix="/api/auth", tags=["auth"])

    @router.get("/providers")
    def providers() -> dict[str, list[str]]:
        """Sign-in providers enabled on this server."""
        return {"providers": auth.providers}

    @router.get("/login/{provider}", response_class=RedirectResponse, status_code=302)
    def login(provider: str, request: Request) -> Response:
        """Start sign-in: redirect to the provider. ``next`` must be a same-origin path such as ``/app``."""
        if provider not in auth.providers:
            raise HTTPException(404, "unknown sign-in provider")
        start = auth.start_login(provider, request.query_params.get("next"))
        response = RedirectResponse(start.redirect_url, status_code=302, headers=_NO_STORE)
        _set_cookie(response, LOGIN_COOKIE, start.state, LOGIN_TTL_S)
        return response

    @router.get("/callback/{provider}", response_class=RedirectResponse, status_code=303)
    def callback(provider: str, request: Request) -> Response:
        """Finish sign-in, set the session cookie and redirect to ``next`` (default ``/app``)."""
        query = request.query_params
        try:
            signin = auth.finish_login(
                provider,
                state=query.get("state"),
                code=query.get("code"),
                error=query.get("error"),
                bound_state=request.cookies.get(LOGIN_COOKIE),
                previous_session_id=request.cookies.get(SESSION_COOKIE),
            )
        except AuthFailed as exc:
            log.warning("sign-in failed provider=%s reason=%s", provider if provider in PROVIDERS else "-", exc.code)
            response = RedirectResponse(FAILED_REDIRECT, status_code=303, headers=_NO_STORE)
            _clear_cookie(response, LOGIN_COOKIE)
            return response
        response = RedirectResponse(signin.next, status_code=303, headers=_NO_STORE)
        _clear_cookie(response, LOGIN_COOKIE)
        _set_cookie(response, SESSION_COOKIE, signin.session_id, SESSION_ABSOLUTE_S)
        return response

    @router.get("/me")
    def me(request: Request, response: Response) -> dict[str, object]:
        """Who is signed in, and the CSRF token to send as ``X-CSRF-Token`` on state-changing requests."""
        response.headers.update(_NO_STORE)
        session = current_session(request)
        if session is None:
            return {"signed_in": False}
        return {
            "signed_in": True,
            "user": {"display_name": session.display_name, "email": session.email, "provider": session.provider},
            "csrf_token": session.csrf_token,
        }

    @router.post("/logout", status_code=204)
    def logout(request: Request) -> Response:
        """End this session. Signed-in callers must send ``X-CSRF-Token``."""
        session = current_session(request)
        if session is not None:
            auth.logout(session)
        response = Response(status_code=204)
        _clear_cookie(response, SESSION_COOKIE)
        return response

    @router.delete("/account", status_code=204)
    def delete_account(request: Request) -> Response:
        """Delete the signed-in user and every session of that user. Requires ``X-CSRF-Token``."""
        session = current_session(request)
        if session is None:  # the gate already refuses this; kept so the route is safe on its own
            raise Rejected(Reason.SIGN_IN_REQUIRED, "sign in first")
        auth.delete_account(session)
        response = Response(status_code=204)
        _clear_cookie(response, SESSION_COOKIE)
        return response

    return router
