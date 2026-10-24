# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-611): Parses an upload with xml.etree.ElementTree defaults."""

import xml.etree.ElementTree as ET

from flask import Flask, request

app = Flask(__name__)


@app.post("/feed")
def feed():
    root = ET.fromstring(request.files["feed"].read())
    return {"items": len(root)}
