# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-94): Agent evaluates the model's reply as a Python expression."""

import anthropic

client = anthropic.Anthropic()


def compute(question: str) -> object:
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=200,
        messages=[{"role": "user", "content": f"Write one Python expression that answers: {question}"}],
    )
    return eval(message.content[0].text)
