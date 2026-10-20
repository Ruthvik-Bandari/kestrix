# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-79): Flask view returns a banner div built by concatenating a message parameter."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/banner")
def banner():
    return "<div class='banner'>" + request.args.get("msg", "") + "</div>"
