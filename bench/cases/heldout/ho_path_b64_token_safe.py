# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): Decodes a base64 token, resolves the path and checks it with str(...).startswith."""

import base64
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
EXPORTS = Path("/srv/app/exports")


@app.get("/export")
def export():
    name = base64.urlsafe_b64decode(request.args["token"]).decode()
    target = (EXPORTS / name).resolve()
    if not str(target).startswith(str(EXPORTS) + "/"):
        abort(404)
    return target.read_bytes()
