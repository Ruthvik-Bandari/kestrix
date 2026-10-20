# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-611): Parses an uploaded XML invoice with the standard library parser."""

import xml.etree.ElementTree as ET

from flask import Flask, request

app = Flask(__name__)


@app.post("/invoices")
def upload_invoice():
    root = ET.fromstring(request.get_data())
    return {"total": root.findtext("total")}
