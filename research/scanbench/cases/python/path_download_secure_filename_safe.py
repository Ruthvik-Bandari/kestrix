# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-22): File download reduces the name with secure_filename."""

import os

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOADS = "/srv/app/uploads"


@app.get("/download")
def download():
    return send_file(os.path.join(UPLOADS, secure_filename(request.args["file"])))
