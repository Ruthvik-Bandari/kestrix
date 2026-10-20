# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-89): Builds an IN list by joining raw id strings from the request."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/items")
def items():
    ids = request.args.getlist("id")
    conn = sqlite3.connect("/srv/app/app.db")
    query = "SELECT name FROM items WHERE id IN (" + ",".join(ids) + ")"
    return {"rows": conn.execute(query).fetchall()}
