# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-79): Flask view returns an HTML f-string with request data (reflected XSS)."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/welcome")
def welcome():
    user = request.args.get("user", "guest")
    return f"<html><body><h2>Welcome back, {user}</h2></body></html>"
