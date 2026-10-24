# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-798): HTTP client with a literal bearer token for a partner API."""

import httpx

PARTNER_API_TOKEN = "f3K9qL2xV8mR4tZ7wB1nC6yH0pJ5sDa"


def list_shipments() -> list[dict]:
    resp = httpx.get(
        "https://partner.example.invalid/v2/shipments",
        headers={"Authorization": f"Bearer {PARTNER_API_TOKEN}"},
        timeout=10,
    )
    return resp.json()["shipments"]
