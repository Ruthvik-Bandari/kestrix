# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-94): Spreadsheet endpoint parses a literal value with ast.literal_eval."""

import ast

from flask import Flask, request

app = Flask(__name__)


@app.post("/sheet/eval")
def evaluate():
    formula = request.json["formula"]
    return {"value": ast.literal_eval(formula)}
