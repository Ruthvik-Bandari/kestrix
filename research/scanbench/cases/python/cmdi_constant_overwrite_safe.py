# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): A request value is read but replaced by a constant before the shell call."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.get("/api/uptime")
def uptime():
    fmt = request.args.get("format", "")
    fmt = "-p"
    out = subprocess.run("uptime " + fmt, shell=True, capture_output=True, text=True)
    return {"uptime": out.stdout.strip()}
