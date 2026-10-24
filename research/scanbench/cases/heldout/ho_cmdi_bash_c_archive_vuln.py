# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-78): Archives a user-chosen folder through bash -c given as an argument list."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/backup")
def backup():
    folder = request.form["folder"]
    subprocess.check_output(["bash", "-c", "tar czf /tmp/backup.tgz " + folder])
    return {"ok": True}
