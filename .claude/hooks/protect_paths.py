#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""PreToolUse hook: block Write/Edit/MultiEdit/NotebookEdit on protected paths.

Reads the Claude Code hook JSON from stdin, takes tool_input.file_path (or
tool_input.notebook_path), resolves it against the project directory, and exits
with code 2 (reason on stderr) when the target is protected:

- .env and .env.* files (except .env.example)
- *.pem and *.key files
- anything under data/raw/, data/locked/ or a secrets/ directory
- anything that resolves outside the project directory (after realpath, so
  ".." segments and symlinks are followed)

Malformed or unexpected input fails closed (exit 2). Otherwise exit 0.

This reduces accidental modification only. It does not intercept shell commands
and is not a sandbox. Stdlib only.
"""

from __future__ import annotations

import json
import os
import sys

PROTECTED_DIR_SEQUENCES = (("data", "raw"), ("data", "locked"), ("secrets",))
PROTECTED_SUFFIXES = (".pem", ".key")
ALLOWED_ENV_NAMES = {".env.example"}


def deny(reason: str) -> None:
    sys.stderr.write(f"protect_paths: blocked: {reason}\n")
    sys.exit(2)


def project_root(payload: dict) -> str:
    root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    if not isinstance(root, str) or not root:
        deny("cannot determine project directory")
    return os.path.realpath(root)


def contains_sequence(parts: list[str], seq: tuple[str, ...]) -> bool:
    n = len(seq)
    return any(tuple(parts[i : i + n]) == seq for i in range(len(parts) - n + 1))


def protected_reason(rel_parts: list[str]) -> str | None:
    lowered = [p.lower() for p in rel_parts]
    dir_parts = lowered[:-1]
    for seq in PROTECTED_DIR_SEQUENCES:
        # Check directories, and also the final component when it IS the protected dir.
        if contains_sequence(dir_parts, seq) or contains_sequence(lowered, seq):
            return f"path is under protected location {'/'.join(seq)}/"
    name = lowered[-1] if lowered else ""
    if (name == ".env" or name.startswith(".env.")) and name not in ALLOWED_ENV_NAMES:
        return "environment files (.env*) are protected"
    if name.endswith(PROTECTED_SUFFIXES):
        return "key material (*.pem, *.key) is protected"
    return None


def main() -> None:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        deny("malformed hook input (not JSON)")
    if not isinstance(payload, dict):
        deny("malformed hook input (not an object)")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        deny("malformed hook input (missing tool_input)")
    target = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not isinstance(target, str) or not target.strip() or "\x00" in target:
        deny("missing or invalid file_path/notebook_path")

    root = project_root(payload)
    joined = target if os.path.isabs(target) else os.path.join(root, target)
    lexical = os.path.normpath(joined)
    resolved = os.path.realpath(joined)

    for candidate in (resolved, lexical):
        try:
            inside = os.path.commonpath([root, candidate]) == root
        except ValueError:
            inside = False
        if not inside:
            deny(f"{target!r} resolves outside the project directory")
        rel = os.path.relpath(candidate, root)
        parts = [] if rel == "." else rel.split(os.sep)
        reason = protected_reason(parts)
        if reason:
            deny(f"{target!r}: {reason}")

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed on anything unexpected
        deny(f"internal error: {type(exc).__name__}")
