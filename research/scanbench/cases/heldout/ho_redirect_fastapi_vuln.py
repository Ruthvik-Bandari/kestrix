# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-601): FastAPI redirect response to a next_url parameter."""

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()


@app.get("/continue")
def continue_to(next_url: str):
    return RedirectResponse(url=next_url)
