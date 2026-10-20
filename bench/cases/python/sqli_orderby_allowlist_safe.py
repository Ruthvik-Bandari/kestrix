# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-89): Sort column chosen from a fixed allowlist before formatting."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
SORTS = {"newest": "created_at DESC", "oldest": "created_at ASC", "total": "total DESC"}


@app.get("/orders")
def orders():
    sort = SORTS.get(request.args.get("sort", ""), "created_at DESC")
    conn = sqlite3.connect("app.db")
    query = "SELECT id, total FROM orders ORDER BY {}".format(sort)
    return {"orders": conn.execute(query).fetchall()}
