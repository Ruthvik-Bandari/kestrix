# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): Opens a percent-decoded name only if its real path stays under the base."""

import os
from urllib.parse import unquote

from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/app/files/"


@app.get("/raw")
def raw():
    path = os.path.realpath(os.path.join(BASE, unquote(request.args["f"])))
    if not path.startswith(BASE):
        abort(404)
    with open(path, "rb") as fh:
        return fh.read()
