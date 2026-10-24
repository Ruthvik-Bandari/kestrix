# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-328): Stores password hashes with unsalted MD5."""

import hashlib


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def check_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored
