# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-78): Archives a user-chosen folder with tar called directly, no shell."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/backup")
def backup():
    folder = request.form["folder"]
    subprocess.check_output(["tar", "czf", "/tmp/backup.tgz", "--", folder])
    return {"ok": True}
