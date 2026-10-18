# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Byte samples shared by the forensics tests."""

import random


def random_bytes(size: int, seed: int = 1234) -> bytes:
    return random.Random(seed).randbytes(size)


def pe_bytes(payload: bytes = b"") -> bytes:
    """Minimal MZ header whose e_lfanew points at a PE signature, followed by ``payload``."""
    head = bytearray(0x80)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    return bytes(head) + payload


def docx_head() -> bytes:
    return b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml" + b"\x00" * 30 + b"word/document.xml"
