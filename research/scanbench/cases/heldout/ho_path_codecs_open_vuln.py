# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-22): Reads a document with codecs.open from a joined request path."""

import codecs
import os

from flask import Flask, request

app = Flask(__name__)
DOCS = "/srv/app/docs"


@app.get("/doc")
def doc():
    with codecs.open(os.path.join(DOCS, request.args["name"]), encoding="utf-8") as fh:
        return fh.read()
