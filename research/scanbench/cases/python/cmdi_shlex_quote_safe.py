# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): Git helper that quotes the branch name before using a shell."""

import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.get("/api/history")
def history():
    branch = shlex.quote(request.args.get("branch", "main"))
    out = subprocess.run(f"git log --oneline {branch} | head -n 20", shell=True, capture_output=True, text=True)
    return {"commits": out.stdout.splitlines()}
