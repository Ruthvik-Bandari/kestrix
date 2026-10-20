# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-89): Text-to-SQL helper executes the model's SQL directly."""

import sqlite3

import anthropic

client = anthropic.Anthropic()


def answer(question: str) -> list[tuple]:
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=300,
        messages=[{"role": "user", "content": f"Write SQLite SQL for the sales table that answers: {question}"}],
    )
    sql = message.content[0].text
    with sqlite3.connect("sales.db") as conn:
        return conn.execute(sql).fetchall()
