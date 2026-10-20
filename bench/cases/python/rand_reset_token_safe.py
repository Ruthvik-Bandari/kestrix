# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-330): Password reset token from secrets."""

import secrets


def make_reset_token() -> str:
    return secrets.token_urlsafe(32)
