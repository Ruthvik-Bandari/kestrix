# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-330): Stores a login challenge made with random.getrandbits in the session."""

import random

from flask import Flask, session

app = Flask(__name__)
app.secret_key = b"replace-me-in-deployment-config"


@app.get("/challenge")
def challenge():
    value = random.getrandbits(64)
    session["challenge"] = value
    return {"challenge": value}
