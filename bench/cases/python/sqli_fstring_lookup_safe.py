# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-89): User lookup with a bound parameter."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/users")
def find_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT id, email FROM users WHERE name = ?", (name,)).fetchall()
    return {"users": rows}
