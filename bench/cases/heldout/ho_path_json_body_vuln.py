# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-22): Writes an upload to a path read from a JSON request body."""

import json

from flask import Flask, request

app = Flask(__name__)


@app.post("/save")
def save():
    meta = json.loads(request.data)
    with open("/srv/app/uploads/" + meta["filename"], "w") as fh:
        fh.write(meta["content"])
    return {"ok": True}
