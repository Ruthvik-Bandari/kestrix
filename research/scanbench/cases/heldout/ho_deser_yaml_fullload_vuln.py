# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-502): Imports a YAML configuration upload with the FullLoader."""

import yaml

from flask import Flask, request

app = Flask(__name__)


@app.post("/config/import")
def import_config():
    config = yaml.load(request.data, Loader=yaml.FullLoader)
    return {"keys": sorted(config)}
