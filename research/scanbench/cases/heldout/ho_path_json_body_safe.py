# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): Writes an upload to a secure_filename of the JSON body's name."""

import json

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.post("/save")
def save():
    meta = json.loads(request.data)
    with open("/srv/app/uploads/" + secure_filename(meta["filename"]), "w") as fh:
        fh.write(meta["content"])
    return {"ok": True}
