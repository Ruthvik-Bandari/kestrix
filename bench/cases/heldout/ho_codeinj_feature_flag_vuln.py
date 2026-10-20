# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-94): Calculator evaluates two query operands formatted into an expression."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/add")
def add():
    a = request.args["a"]
    b = request.args["b"]
    return {"sum": eval(f"{a} + {b}")}
