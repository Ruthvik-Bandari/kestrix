# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-601): Login redirects to the ?next= URL as given."""

from flask import Flask, redirect, request

app = Flask(__name__)


@app.post("/login")
def login():
    # ... credentials checked here ...
    return redirect(request.args.get("next", "/"))
