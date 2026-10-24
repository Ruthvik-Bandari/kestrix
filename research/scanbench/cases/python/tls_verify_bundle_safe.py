# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-295): Internal API client that trusts a private CA bundle."""

import requests

CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"


def fetch_inventory(base_url: str, token: str) -> dict:
    resp = requests.get(f"{base_url}/inventory", headers={"Authorization": f"Bearer {token}"}, verify=CA_BUNDLE, timeout=10)
    resp.raise_for_status()
    return resp.json()
