# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-643): ElementTree iterates the books and compares the id attribute in Python."""

import xml.etree.ElementTree as ET

from flask import Flask, request

app = Flask(__name__)
CATALOG = ET.parse("/srv/app/catalog.xml").getroot()


@app.get("/books")
def books():
    book_id = request.args["id"]
    found = [b for b in CATALOG.iter("book") if b.get("id") == book_id]
    return {"titles": [b.findtext("title") for b in found]}
