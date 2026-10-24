# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-502): Restores a cart object from a cookie with pickle."""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.get("/cart")
def cart():
    raw = request.cookies.get("cart", "")
    items = pickle.loads(base64.b64decode(raw)) if raw else []
    return {"items": items}
