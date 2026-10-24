# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): Coding agent maps the model's choice onto a fixed set of commands."""

import subprocess

from openai import OpenAI

client = OpenAI()
COMMANDS = {"reinstall": ["uv", "sync"], "clean": ["git", "clean", "-n"], "test": ["uv", "run", "pytest", "-q"]}


def run_suggested_fix(error_log: str) -> str:
    reply = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role": "user", "content": f"Answer reinstall, clean or test for this error:\n{error_log}"}],
    )
    choice = (reply.choices[0].message.content or "").strip().lower()
    if choice not in COMMANDS:
        return "no action"
    return subprocess.run(COMMANDS[choice], capture_output=True, text=True, check=False).stdout
