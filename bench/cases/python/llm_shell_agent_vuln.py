# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-78): Coding agent runs the model's suggested shell command."""

import subprocess

from openai import OpenAI

client = OpenAI()


def run_suggested_fix(error_log: str) -> str:
    reply = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role": "user", "content": f"Give one shell command that fixes this build error:\n{error_log}"}],
    )
    command = reply.choices[0].message.content
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
