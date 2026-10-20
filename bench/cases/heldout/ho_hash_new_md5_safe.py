# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-328): Signs webhook payloads with SHA-256."""

import hashlib


def sign(secret: bytes, payload: bytes) -> str:
    h = hashlib.new("sha256")
    h.update(secret + payload)
    return h.hexdigest()
