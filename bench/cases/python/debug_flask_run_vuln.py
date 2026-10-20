# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-489): Starts the Flask app in debug mode on all interfaces."""

from flask import Flask

app = Flask(__name__)


@app.get("/")
def index():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
