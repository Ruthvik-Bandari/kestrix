# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-502): Imports a YAML configuration upload with safe_load."""

import yaml

from flask import Flask, request

app = Flask(__name__)


@app.post("/config/import")
def import_config():
    config = yaml.safe_load(request.data)
    return {"keys": sorted(config)}
