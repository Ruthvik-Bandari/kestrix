# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-643): lxml xpath() with the user name passed as an XPath variable."""

from lxml import etree
from flask import Flask, request

app = Flask(__name__)
USERS = etree.parse("/srv/app/users.xml")


@app.get("/users/find")
def find_user():
    name = request.args["name"]
    matches = USERS.xpath("//user[name=$name]/email/text()", name=name)
    return {"emails": [str(m) for m in matches]}
