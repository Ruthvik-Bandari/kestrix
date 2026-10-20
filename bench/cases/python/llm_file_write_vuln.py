# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-22): Agent writes generated code to the file path the model chose."""

import json
from pathlib import Path

from openai import OpenAI

client = OpenAI()
WORKSPACE = Path("/srv/agent/workspace")


def apply_edit(task: str) -> None:
    reply = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{"role": "user", "content": f'Reply with JSON {{"path": ..., "content": ...}} for: {task}'}],
    )
    edit = json.loads(reply.choices[0].message.content)
    with open(WORKSPACE / edit["path"], "w", encoding="utf-8") as fh:
        fh.write(edit["content"])
