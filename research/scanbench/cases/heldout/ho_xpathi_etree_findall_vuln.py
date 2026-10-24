# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-643): ElementTree findall() with a book id from the query string inside the path."""

import xml.etree.ElementTree as ET

from flask import Flask, request

app = Flask(__name__)
CATALOG = ET.parse("/srv/app/catalog.xml").getroot()


@app.get("/books")
def books():
    book_id = request.args["id"]
    found = CATALOG.findall(f".//book[@id='{book_id}']")
    return {"titles": [b.findtext("title") for b in found]}
