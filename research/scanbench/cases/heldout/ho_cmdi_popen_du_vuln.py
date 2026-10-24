# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-78): Disk usage report passes a request path to os.popen."""

import os

from flask import Flask, request

app = Flask(__name__)


@app.get("/usage")
def usage():
    report = os.popen("du -sh " + request.args["dir"]).read()
    return {"report": report}
