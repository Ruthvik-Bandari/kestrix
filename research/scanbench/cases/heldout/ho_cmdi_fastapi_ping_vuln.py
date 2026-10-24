# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-78): FastAPI endpoint pings a host parameter with shell=True."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/diag/ping")
def ping(host: str):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
