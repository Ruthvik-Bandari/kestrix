# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-22): Decodes a base64 download token into a file name and reads it."""

import base64
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
EXPORTS = Path("/srv/app/exports")


@app.get("/export")
def export():
    name = base64.urlsafe_b64decode(request.args["token"]).decode()
    return (EXPORTS / name).read_bytes()
