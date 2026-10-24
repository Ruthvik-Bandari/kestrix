# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-347): Reads the user id from a JWT without checking its signature."""

import jwt
from flask import Flask, request

app = Flask(__name__)


@app.get("/me")
def me():
    token = request.headers["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return {"user": claims["sub"]}
