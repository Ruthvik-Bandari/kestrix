# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-78): Runs a user-supplied filter through sh -c given as an argument list (no shell=True)."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/logs/grep")
def grep_logs():
    pattern = request.json["pattern"]
    out = subprocess.run(["sh", "-c", f"grep {pattern} /var/log/app.log"], capture_output=True, text=True)
    return {"lines": out.stdout.splitlines()}
