# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-90): python-ldap search_s with a uid filter built from a form field."""

import ldap

from flask import Flask, request

app = Flask(__name__)


@app.post("/directory/lookup")
def lookup():
    username = request.form["username"]
    conn = ldap.initialize("ldap://ldap.internal.invalid")
    results = conn.search_s("ou=people,dc=example,dc=org", ldap.SCOPE_SUBTREE, f"(uid={username})")
    return {"count": len(results)}
