# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-94): Spreadsheet endpoint evaluates a formula from the JSON body."""

from flask import Flask, request

app = Flask(__name__)


@app.post("/sheet/eval")
def evaluate():
    formula = request.json["formula"]
    return {"value": eval(formula)}
