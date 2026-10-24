# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-22): Writes a file whose LLM-chosen name is reduced with os.path.basename."""

import json
import os

import anthropic

client = anthropic.Anthropic()
NOTES = "/srv/app/notes"


def save_note(prompt: str) -> None:
    reply = client.messages.create(model="claude-x", max_tokens=200, messages=[{"role": "user", "content": prompt}])
    note = json.loads(reply.content[0].text)
    with open(os.path.join(NOTES, os.path.basename(note["filename"])), "w") as fh:
        fh.write(note["body"])
