# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): Network check endpoint: argument list, no shell, host validated."""

import ipaddress
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.get("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        address = str(ipaddress.ip_address(host))
    except ValueError:
        abort(400)
    result = subprocess.run(["ping", "-c", "1", address], capture_output=True, text=True, check=False)
    return {"ok": result.returncode == 0, "output": result.stdout}
