# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-78): Async job runner starts git with the ref as a separate argument."""

import asyncio

from flask import Flask, request

app = Flask(__name__)


@app.post("/jobs")
async def start_job():
    ref = request.get_json()["ref"]
    proc = await asyncio.create_subprocess_exec("git", "log", "--oneline", ref)
    await proc.wait()
    return {"code": proc.returncode}
