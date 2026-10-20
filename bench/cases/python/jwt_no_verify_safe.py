# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-347): Verifies the JWT with a key and a fixed algorithm."""

import os

import jwt
from flask import Flask, request

app = Flask(__name__)


@app.get("/me")
def me():
    token = request.headers["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
    return {"user": claims["sub"]}
