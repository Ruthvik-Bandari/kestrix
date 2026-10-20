# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-79): FastAPI HTMLResponse escapes the name parameter with html.escape."""

import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "world"):
    return HTMLResponse("<p>Hello, " + html.escape(name) + "!</p>")
