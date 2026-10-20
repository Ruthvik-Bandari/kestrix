# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-330): Stores a login challenge made with secrets.randbits in the session."""

import secrets

from flask import Flask, session

app = Flask(__name__)
app.secret_key = b"replace-me-in-deployment-config"


@app.get("/challenge")
def challenge():
    value = secrets.randbits(64)
    session["challenge"] = value
    return {"challenge": value}
