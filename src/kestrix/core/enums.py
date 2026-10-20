# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``TextEnum``: a string enum that behaves the same on Python 3.10 and newer.

It replaces ``enum.StrEnum`` (Python 3.11+). Members are ``str`` instances equal to their value,
and ``str()``, ``format()`` and f-strings give the value, as with ``StrEnum``. Members are always
declared with explicit string values; ``auto()`` is not used.
"""

from enum import Enum


class TextEnum(str, Enum):
    def __str__(self) -> str:
        return str(self.value)
