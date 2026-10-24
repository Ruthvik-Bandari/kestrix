# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-78): Async job runner starts zsh -c with a script taken from the request body."""

import asyncio

from flask import Flask, request

app = Flask(__name__)


@app.post("/jobs")
async def start_job():
    script = request.get_json()["script"]
    proc = await asyncio.create_subprocess_exec("zsh", "-c", script)
    await proc.wait()
    return {"code": proc.returncode}
