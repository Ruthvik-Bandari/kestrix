# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): Reads a document with codecs.open after os.path.basename."""

import codecs
import os

from flask import Flask, request

app = Flask(__name__)
DOCS = "/srv/app/docs"


@app.get("/doc")
def doc():
    name = os.path.basename(request.args["name"])
    with codecs.open(os.path.join(DOCS, name), encoding="utf-8") as fh:
        return fh.read()
