# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-89): Orders a listing by a column name from the query string."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/orders")
def orders():
    column = request.args.get("sort", "created_at")
    conn = sqlite3.connect("/srv/app/app.db")
    rows = conn.execute(f"SELECT id, total FROM orders ORDER BY {column}").fetchall()
    return {"rows": rows}
