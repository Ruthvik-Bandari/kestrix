# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-614): Flask sets a login hint cookie without secure or httponly."""

from flask import Flask, make_response, request

app = Flask(__name__)


@app.post("/login")
def login():
    response = make_response({"ok": True})
    response.set_cookie("login_hint", request.form["email"])
    return response
