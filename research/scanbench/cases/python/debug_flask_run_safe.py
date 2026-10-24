# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-489): Starts the Flask app without debug mode on loopback."""

from flask import Flask

app = Flask(__name__)


@app.get("/")
def index():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
