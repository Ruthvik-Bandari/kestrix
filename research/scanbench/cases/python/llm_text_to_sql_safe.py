# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-89): Model only picks a region, which is bound as a parameter."""

import sqlite3

import anthropic

client = anthropic.Anthropic()


def answer(question: str) -> list[tuple]:
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=20,
        messages=[{"role": "user", "content": f"Which sales region does this ask about? One word: {question}"}],
    )
    region = message.content[0].text.strip()
    with sqlite3.connect("sales.db") as conn:
        return conn.execute("SELECT month, total FROM sales WHERE region = ?", (region,)).fetchall()
