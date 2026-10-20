# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-79): Greeting marked safe with request data inside."""

from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.get("/hello")
def hello():
    name = request.args.get("name", "friend")
    return Markup(f"<h1>Hello, {name}!</h1>")
