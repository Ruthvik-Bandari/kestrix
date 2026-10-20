# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-502): Imports an uploaded YAML pipeline definition with the full loader."""

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/pipelines/import")
def import_pipeline():
    spec = yaml.load(request.files["spec"].read(), Loader=yaml.Loader)
    return {"steps": len(spec.get("steps", []))}
