# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-89): Orders a listing by a column checked against an allowlist first."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
SORTABLE = ("created_at", "total", "status")


@app.get("/orders")
def orders():
    column = request.args.get("sort", "created_at")
    if column not in SORTABLE:
        return {"error": "bad sort column"}, 400
    conn = sqlite3.connect("/srv/app/app.db")
    rows = conn.execute(f"SELECT id, total FROM orders ORDER BY {column}").fetchall()
    return {"rows": rows}
