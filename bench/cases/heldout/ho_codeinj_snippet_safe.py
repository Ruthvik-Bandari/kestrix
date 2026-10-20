# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-94): Startup hook executes a snippet chosen from a constant table by a constant key."""

from flask import Flask

app = Flask(__name__)

HOOKS = {"warmup": "import json", "noop": "pass"}


@app.post("/console")
def console():
    snippet = HOOKS["warmup"]
    exec(snippet)
    return "done"
