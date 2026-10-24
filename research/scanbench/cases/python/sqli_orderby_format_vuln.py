# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-89): Sort column taken from the query string and formatted into ORDER BY."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/orders")
def orders():
    sort = request.args.get("sort", "created_at")
    conn = sqlite3.connect("app.db")
    query = "SELECT id, total FROM orders ORDER BY {}".format(sort)
    return {"orders": conn.execute(query).fetchall()}
