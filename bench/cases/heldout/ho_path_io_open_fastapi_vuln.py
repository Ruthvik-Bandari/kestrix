# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-22): FastAPI report endpoint opens an f-string path with io.open."""

import io

from fastapi import FastAPI

app = FastAPI()


@app.get("/reports/{name}")
def report(name: str):
    with io.open(f"/srv/reports/{name}", encoding="utf-8") as fh:
        return {"body": fh.read()}
