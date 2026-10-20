# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-22): File download joins the requested name onto the upload folder."""

import os

from flask import Flask, request, send_file

app = Flask(__name__)
UPLOADS = "/srv/app/uploads"


@app.get("/download")
def download():
    return send_file(os.path.join(UPLOADS, request.args["file"]))
