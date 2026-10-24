# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-330): Sends an auth challenge header built from random.choices."""

import random
import string

from flask import Flask, make_response

app = Flask(__name__)


@app.get("/auth/begin")
def begin():
    response = make_response("", 401)
    response.headers["X-Auth-Challenge"] = "".join(random.choices(string.ascii_letters, k=24))
    return response
