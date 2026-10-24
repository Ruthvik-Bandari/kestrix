# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-330): random used to shuffle quiz questions (not a security use)."""

import random


def quiz_order(questions: list[str], seed: int | None = None) -> list[str]:
    order = list(questions)
    random.Random(seed).shuffle(order)
    return order
