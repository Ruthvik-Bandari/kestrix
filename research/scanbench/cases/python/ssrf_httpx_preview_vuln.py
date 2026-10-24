# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-918): Link preview fetches a URL from the query string with httpx."""

import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/preview")
async def preview(url: str) -> dict[str, str]:
    async with httpx.AsyncClient(timeout=5) as client:
        page = await client.get(url)
    return {"title": page.text[:200]}
