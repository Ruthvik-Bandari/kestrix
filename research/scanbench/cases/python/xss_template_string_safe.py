# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-79): Request data passed to the template as a variable."""

from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string("<p>Results for {{ q }}</p>", q=q)
