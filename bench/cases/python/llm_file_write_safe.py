# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-22): Agent writes generated code only inside its workspace."""

import json
from pathlib import Path

from openai import OpenAI

client = OpenAI()
WORKSPACE = Path("/srv/agent/workspace").resolve()


def apply_edit(task: str) -> None:
    reply = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{"role": "user", "content": f'Reply with JSON {{"path": ..., "content": ...}} for: {task}'}],
    )
    edit = json.loads(reply.choices[0].message.content)
    target = (WORKSPACE / edit["path"]).resolve()
    if not target.is_relative_to(WORKSPACE):
        raise ValueError("path escapes the workspace")
    target.write_text(edit["content"], encoding="utf-8")
