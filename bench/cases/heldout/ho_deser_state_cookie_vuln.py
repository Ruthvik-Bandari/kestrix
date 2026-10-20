# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-502): Restores UI state by unpickling a base64 cookie."""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.get("/state")
def state():
    blob = base64.b64decode(request.cookies["state"])
    return {"state": pickle.loads(blob)}
