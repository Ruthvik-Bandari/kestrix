# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-295): urllib download with an unverified SSL context."""

import ssl
import urllib.request


def download(url: str) -> bytes:
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(url, context=ctx, timeout=10) as resp:
        return resp.read()
