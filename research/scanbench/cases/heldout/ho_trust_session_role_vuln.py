# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-501): Copies a role from the form straight into the session."""

from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = b"replace-me-in-deployment-config"


@app.post("/profile")
def profile():
    session["role"] = request.form["role"]
    return {"ok": True}
