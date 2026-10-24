# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): FastAPI report endpoint maps the name to a fixed file through a table."""

import io

from fastapi import FastAPI

app = FastAPI()
REPORTS = {"daily": "/srv/reports/daily.txt", "weekly": "/srv/reports/weekly.txt"}


@app.get("/reports/{name}")
def report(name: str):
    with io.open(REPORTS.get(name, "/srv/reports/daily.txt"), encoding="utf-8") as fh:
        return {"body": fh.read()}
