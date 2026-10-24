# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-611): Parses uploaded XML with an lxml parser that does not resolve entities."""

from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.post("/import")
def import_xml():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    root = etree.fromstring(request.data, parser)
    return {"tag": root.tag}
