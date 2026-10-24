# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-94): Agent parses the model's reply as JSON and dispatches to known functions."""

import json
import math

import anthropic

client = anthropic.Anthropic()
TOOLS = {"sqrt": math.sqrt, "log10": math.log10}


def compute(question: str) -> float:
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=200,
        messages=[{"role": "user", "content": f'Reply with JSON {{"tool": "sqrt"|"log10", "x": number}}: {question}'}],
    )
    call = json.loads(message.content[0].text)
    return TOOLS[call["tool"]](float(call["x"]))
