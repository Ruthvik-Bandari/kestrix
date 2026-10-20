# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-89): Numeric id converted with int() before it is formatted into SQL."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/invoice")
def invoice():
    invoice_id = int(request.args["id"])
    conn = sqlite3.connect("app.db")
    row = conn.execute(f"SELECT id, total FROM invoices WHERE id = {invoice_id}").fetchone()
    return {"invoice": row}
