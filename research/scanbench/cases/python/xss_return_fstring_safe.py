# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-79): Flask view escapes request data before returning HTML."""

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.get("/welcome")
def welcome():
    user = escape(request.args.get("user", "guest"))
    return f"<html><body><h2>Welcome back, {user}</h2></body></html>"
