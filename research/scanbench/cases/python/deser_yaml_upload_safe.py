# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-502): Imports an uploaded YAML pipeline definition with safe_load."""

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/pipelines/import")
def import_pipeline():
    spec = yaml.safe_load(request.files["spec"].read())
    return {"steps": len(spec.get("steps", []))}
