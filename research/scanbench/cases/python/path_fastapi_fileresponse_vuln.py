# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-22): FastAPI report download built from a path parameter."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()
REPORTS = Path("/srv/reports")


@app.get("/reports/{name}")
def report(name: str) -> FileResponse:
    return FileResponse(REPORTS / name)
