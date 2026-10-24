# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-614): Flask sets a login hint cookie with secure, httponly and samesite."""

from flask import Flask, make_response, request

app = Flask(__name__)


@app.post("/login")
def login():
    response = make_response({"ok": True})
    response.set_cookie("login_hint", request.form["email"], secure=True, httponly=True, samesite="Lax")
    return response
