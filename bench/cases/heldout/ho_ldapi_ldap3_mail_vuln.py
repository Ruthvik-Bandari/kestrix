# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-90): ldap3 search concatenates an e-mail address into the filter."""

from ldap3 import Connection, Server
from flask import Flask, request

app = Flask(__name__)


@app.get("/people")
def people():
    email = request.args.get("email", "")
    conn = Connection(Server("ldap.internal.invalid"), auto_bind=True)
    conn.search("dc=example,dc=org", "(&(objectClass=person)(mail=" + email + "))", attributes=["cn"])
    return {"entries": len(conn.entries)}
