# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-328): Signs webhook payloads with hashlib.new('md5')."""

import hashlib


def sign(secret: bytes, payload: bytes) -> str:
    h = hashlib.new("md5")
    h.update(secret + payload)
    return h.hexdigest()
