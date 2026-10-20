# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-611): Parses an upload with pulldom through a SAX parser with external entities enabled."""

from xml.dom import pulldom
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges

from flask import Flask, request

app = Flask(__name__)


@app.post("/orders/import")
def import_orders():
    parser = make_parser()
    parser.setFeature(feature_external_ges, True)
    events = pulldom.parseString(request.data.decode(), parser=parser)
    return {"events": sum(1 for _ in events)}
