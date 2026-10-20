# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-94): Admin endpoint that runs an uploaded plugin snippet."""

from flask import Flask, request

app = Flask(__name__)
PLUGINS: dict[str, object] = {}


@app.post("/admin/plugins")
def install_plugin():
    namespace: dict[str, object] = {}
    exec(request.get_data(as_text=True), namespace)
    PLUGINS[request.args["name"]] = namespace.get("run")
    return {"installed": True}
