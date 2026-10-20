# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The scanner's one refusal exception, with the same reason codes the Kestrix workbench uses."""

from __future__ import annotations

from enum import Enum


class Reason(str, Enum):
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_INPUT = "invalid_input"

    def __str__(self) -> str:
        return self.value


class Rejected(Exception):
    """Raised for invalid input: a missing path, a bad baseline, a bad diff base or a bad configuration."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail
