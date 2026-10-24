# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-94): Plugins are chosen from an allowlist of installed modules."""

import importlib

from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED = {"csv_export": "app.plugins.csv_export", "pdf_export": "app.plugins.pdf_export"}
PLUGINS: dict[str, object] = {}


@app.post("/admin/plugins")
def install_plugin():
    name = request.args["name"]
    if name not in ALLOWED:
        abort(404)
    PLUGINS[name] = importlib.import_module(ALLOWED[name]).run
    return {"installed": True}
