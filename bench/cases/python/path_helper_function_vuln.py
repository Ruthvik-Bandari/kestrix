# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-22): The path is built in a helper and opened in the view (two functions)."""

import os

from flask import Flask, request

app = Flask(__name__)
NOTES = "/srv/notes"


def note_path(name: str) -> str:
    return os.path.join(NOTES, name)


@app.get("/notes")
def read_note():
    with open(note_path(request.args["name"]), encoding="utf-8") as fh:
        return {"text": fh.read()}
