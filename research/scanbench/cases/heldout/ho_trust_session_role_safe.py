# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-501): Stores the role in the session only after checking it against an allowlist."""

from flask import Flask, abort, request, session

app = Flask(__name__)
app.secret_key = b"replace-me-in-deployment-config"
ROLES = ("viewer", "editor")


@app.post("/profile")
def profile():
    role = request.form["role"]
    if role not in ROLES:
        abort(400)
    session["role"] = role
    return {"ok": True}
