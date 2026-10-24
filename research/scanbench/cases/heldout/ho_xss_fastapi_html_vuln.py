# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-79): FastAPI HTMLResponse concatenates a name parameter into markup."""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "world"):
    return HTMLResponse("<p>Hello, " + name + "!</p>")
