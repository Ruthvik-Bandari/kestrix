# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-79): Flask view returns the message as JSON, not HTML."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/banner")
def banner():
    return jsonify({"banner": request.args.get("msg", "")})
