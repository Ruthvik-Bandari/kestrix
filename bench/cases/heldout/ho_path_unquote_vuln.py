# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-22): Opens a percent-decoded file name from the query string."""

from urllib.parse import unquote

from flask import Flask, request

app = Flask(__name__)


@app.get("/raw")
def raw():
    path = "/srv/app/files/" + unquote(request.args["f"])
    with open(path, "rb") as fh:
        return fh.read()
