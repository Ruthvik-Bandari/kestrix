# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-90): FastAPI group search accepts only group names from a fixed allowlist."""

from fastapi import FastAPI, HTTPException
from ldap3 import Connection, Server

app = FastAPI()
KNOWN_GROUPS = {"admins", "developers", "support"}


@app.get("/groups/members")
def members(group: str):
    if group not in KNOWN_GROUPS:
        raise HTTPException(status_code=404)
    conn = Connection(Server("ldap.internal.invalid"), auto_bind=True)
    conn.search("ou=groups,dc=example,dc=org", "(cn=%s)" % group, attributes=["member"])
    return {"entries": len(conn.entries)}
