# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-89): Builds an IN list of placeholders and binds the ids."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/items")
def items():
    ids = request.args.getlist("id")
    conn = sqlite3.connect("/srv/app/app.db")
    placeholders = ",".join("?" for _ in ids)
    query = "SELECT name FROM items WHERE id IN (" + placeholders + ")"
    return {"rows": conn.execute(query, ids).fetchall()}
