# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-502): Restores the cart from a JSON cookie."""

import base64
import json

from flask import Flask, request

app = Flask(__name__)


@app.get("/cart")
def cart():
    raw = request.cookies.get("cart", "")
    items = json.loads(base64.b64decode(raw)) if raw else []
    return {"items": [str(i) for i in items]}
