# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-330): Issues a session id cookie made with random.randint."""

import random

from flask import Flask, make_response

app = Flask(__name__)


@app.post("/start")
def start():
    response = make_response({"ok": True})
    response.set_cookie("sid", str(random.randint(10**8, 10**9)), secure=True, httponly=True)
    return response
