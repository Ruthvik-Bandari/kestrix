# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-22): FastAPI report download with a resolve-and-contain check."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
REPORTS = Path("/srv/reports").resolve()


@app.get("/reports/{name}")
def report(name: str) -> FileResponse:
    target = (REPORTS / name).resolve()
    if not target.is_relative_to(REPORTS):
        raise HTTPException(status_code=404)
    return FileResponse(target)
