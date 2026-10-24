# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-94): Admin console executes a snippet posted in a form."""

from flask import Flask, request

app = Flask(__name__)


@app.post("/console")
def console():
    snippet = request.form["snippet"]
    exec(snippet)
    return "done"
