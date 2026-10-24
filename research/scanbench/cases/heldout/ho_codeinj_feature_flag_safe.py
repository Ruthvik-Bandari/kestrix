# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-94): Calculator evaluates a constant expression; the request branch is disabled by a constant flag."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/add")
def add():
    expression = "1 + 1"
    if False:
        expression = request.args["expr"]
    return {"sum": eval(expression)}
