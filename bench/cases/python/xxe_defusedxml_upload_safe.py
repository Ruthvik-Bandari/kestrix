# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-611): Parses an uploaded XML invoice with defusedxml."""

import defusedxml.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)


@app.post("/invoices")
def upload_invoice():
    root = ET.fromstring(request.get_data())
    return {"total": root.findtext("total")}
