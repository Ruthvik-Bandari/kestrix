# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-611): Turns on external general entities in a SAX parser before parsing an upload."""

import xml.sax
from xml.sax.handler import ContentHandler, feature_external_ges

from flask import Flask, request

app = Flask(__name__)


@app.post("/feed")
def feed():
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)
    parser.setContentHandler(ContentHandler())
    parser.parse(request.files["feed"].stream)
    return {"ok": True}
