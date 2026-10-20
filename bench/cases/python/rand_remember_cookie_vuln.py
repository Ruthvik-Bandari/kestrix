# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-330): Remember-me cookie value from random.random()."""

import random

from flask import Flask, make_response

app = Flask(__name__)


@app.post("/remember")
def remember():
    value = str(random.random())[2:]
    response = make_response({"ok": True})
    response.set_cookie("remember", value, httponly=True, secure=True)
    return response
