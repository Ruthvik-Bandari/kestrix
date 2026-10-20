# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-78): FastAPI endpoint runs one of a fixed set of diagnostic commands with shell=True."""

import subprocess

from fastapi import FastAPI

app = FastAPI()

DIAGNOSTICS = {"disk": "df -h", "memory": "free -m", "load": "uptime"}


@app.get("/diag/run")
def run_diagnostic():
    command = DIAGNOSTICS["disk"]
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
