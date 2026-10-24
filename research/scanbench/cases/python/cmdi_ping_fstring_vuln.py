# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-78): Network check endpoint that pings a host from the query string."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.get("/api/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"ok": result.returncode == 0, "output": result.stdout}
