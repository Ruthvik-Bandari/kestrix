# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-614): FastAPI sets an auth cookie with secure and httponly."""

import secrets

from fastapi import FastAPI, Response

app = FastAPI()


@app.post("/session")
def create_session(response: Response):
    response.set_cookie(key="auth", value=secrets.token_urlsafe(32), secure=True, httponly=True, samesite="strict")
    return {"ok": True}
