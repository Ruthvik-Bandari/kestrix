# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-601): FastAPI redirect to a page chosen from a fixed table."""

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()
PAGES = {"home": "/", "billing": "/account/billing"}


@app.get("/continue")
def continue_to(page: str):
    return RedirectResponse(url=PAGES.get(page, "/"))
