# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): Runs grep directly with the pattern as one argument."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/logs/grep")
def grep_logs():
    pattern = request.json["pattern"]
    out = subprocess.run(["grep", "-e", pattern, "/var/log/app.log"], capture_output=True, text=True, check=False)
    return {"lines": out.stdout.splitlines()}
