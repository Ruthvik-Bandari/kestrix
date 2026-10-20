# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-90): FastAPI group search formats the group parameter into an ldap3 filter."""

from fastapi import FastAPI
from ldap3 import Connection, Server

app = FastAPI()


@app.get("/groups/members")
def members(group: str):
    conn = Connection(Server("ldap.internal.invalid"), auto_bind=True)
    conn.search("ou=groups,dc=example,dc=org", "(cn=%s)" % group, attributes=["member"])
    return {"entries": len(conn.entries)}
