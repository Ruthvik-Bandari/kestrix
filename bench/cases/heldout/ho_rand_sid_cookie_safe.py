# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-330): Issues a session id cookie made with secrets.token_hex."""

import secrets

from flask import Flask, make_response

app = Flask(__name__)


@app.post("/start")
def start():
    response = make_response({"ok": True})
    response.set_cookie("sid", secrets.token_hex(16), secure=True, httponly=True)
    return response
