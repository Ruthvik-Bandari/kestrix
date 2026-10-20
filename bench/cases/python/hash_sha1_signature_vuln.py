# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-328): Signs download links with SHA-1 of secret plus path."""

import hashlib

SECRET = "download-signing-salt"


def sign(path: str) -> str:
    return hashlib.sha1((SECRET + path).encode()).hexdigest()
