# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-328): Computes an ETag with MD5 marked usedforsecurity=False."""

import hashlib


def etag(content: bytes) -> str:
    return hashlib.md5(content, usedforsecurity=False).hexdigest()
