# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-78): Disk usage report formats a constant directory into an os.popen command."""

import os

from flask import Flask

app = Flask(__name__)
DATA_DIR = "/var/lib/app"


@app.get("/usage")
def usage():
    command = "du -sh {}".format(DATA_DIR)
    report = os.popen(command).read()
    return {"report": report}
