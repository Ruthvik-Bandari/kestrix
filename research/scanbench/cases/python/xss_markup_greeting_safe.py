# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-79): Greeting with the name escaped."""

from flask import Flask, request
from markupsafe import Markup, escape

app = Flask(__name__)


@app.get("/hello")
def hello():
    name = request.args.get("name", "friend")
    return Markup("<h1>Hello, {}!</h1>").format(escape(name))
