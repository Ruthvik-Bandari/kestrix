# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-502): Restores UI state by decoding JSON from a base64 cookie."""

import base64
import json

from flask import Flask, request

app = Flask(__name__)


@app.get("/state")
def state():
    blob = base64.b64decode(request.cookies["state"])
    return {"state": json.loads(blob)}
