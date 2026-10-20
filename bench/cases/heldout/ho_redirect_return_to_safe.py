# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-601): Logout rejects return_to values that name a host, using urlparse."""

from urllib.parse import urlparse

from flask import Flask, abort, redirect, request

app = Flask(__name__)


@app.get("/logout")
def logout():
    target = request.args["return_to"]
    if urlparse(target).netloc:
        abort(400)
    return redirect(target)
