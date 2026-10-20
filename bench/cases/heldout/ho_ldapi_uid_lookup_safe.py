# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-90): python-ldap search_s with the uid escaped by ldap.filter.escape_filter_chars."""

import ldap
from ldap.filter import escape_filter_chars

from flask import Flask, request

app = Flask(__name__)


@app.post("/directory/lookup")
def lookup():
    username = escape_filter_chars(request.form["username"])
    conn = ldap.initialize("ldap://ldap.internal.invalid")
    results = conn.search_s("ou=people,dc=example,dc=org", ldap.SCOPE_SUBTREE, f"(uid={username})")
    return {"count": len(results)}
