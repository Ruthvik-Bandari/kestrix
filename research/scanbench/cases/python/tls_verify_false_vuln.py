# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-295): Internal API client with certificate checks turned off."""

import requests


def fetch_inventory(base_url: str, token: str) -> dict:
    resp = requests.get(f"{base_url}/inventory", headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()
