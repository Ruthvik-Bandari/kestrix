# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-90): ldap3 search escapes the e-mail address with ldap3.utils.conv.escape_filter_chars."""

from ldap3 import Connection, Server
from ldap3.utils.conv import escape_filter_chars
from flask import Flask, request

app = Flask(__name__)


@app.get("/people")
def people():
    email = escape_filter_chars(request.args.get("email", ""))
    conn = Connection(Server("ldap.internal.invalid"), auto_bind=True)
    conn.search("dc=example,dc=org", "(&(objectClass=person)(mail=" + email + "))", attributes=["cn"])
    return {"entries": len(conn.entries)}
