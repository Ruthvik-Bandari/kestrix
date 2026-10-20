# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-643): lxml xpath() with a user name formatted into the expression."""

from lxml import etree
from flask import Flask, request

app = Flask(__name__)
USERS = etree.parse("/srv/app/users.xml")


@app.get("/users/find")
def find_user():
    name = request.args["name"]
    matches = USERS.xpath(f"//user[name='{name}']/email/text()")
    return {"emails": [str(m) for m in matches]}
