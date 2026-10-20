# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-601): Login redirects only to a local path."""

from urllib.parse import urlsplit

from flask import Flask, redirect, request

app = Flask(__name__)


@app.post("/login")
def login():
    target = request.args.get("next", "/")
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        target = "/"
    return redirect(target)
