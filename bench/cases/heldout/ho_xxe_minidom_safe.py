# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-611): Parses an upload with xml.dom.minidom defaults."""

from xml.dom import minidom

from flask import Flask, request

app = Flask(__name__)


@app.post("/orders/import")
def import_orders():
    doc = minidom.parseString(request.data)
    return {"orders": len(doc.getElementsByTagName("order"))}
