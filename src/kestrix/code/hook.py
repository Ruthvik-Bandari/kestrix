# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Claude Code PostToolUse hook: scan the file a Write, Edit or MultiEdit just changed.

Input is the hook JSON on stdin; the file path comes from ``tool_input.file_path`` or from
``file_path`` entries in ``tool_input.edits``. Output is a ``hookSpecificOutput`` object whose
``additionalContext`` lists the medium-or-worse findings with their fixes, or nothing when there
are none. The caller fails open: any error means no output and exit code 0.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analyze import scan
from .models import SEVERITY_RANK, Finding
from .walk import is_within

MAX_STDIN_BYTES = 10 * 1024 * 1024
MAX_LISTED = 20
MAX_CONTEXT_CHARS = 6000
_MIN_RANK = SEVERITY_RANK["medium"]


def hook_paths(payload: Any) -> list[Path]:
    if not isinstance(payload, dict):
        return []
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return []
    names = [tool_input.get("file_path")]
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        names.extend(edit.get("file_path") for edit in edits if isinstance(edit, dict))
    unique = dict.fromkeys(name for name in names if isinstance(name, str) and name)
    return [Path(name) for name in unique]


def hook_response(raw: str) -> str | None:
    """The hook's stdout for this payload, or None when there is nothing at medium severity or above."""
    payload = json.loads(raw)
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    lines: list[str] = []
    total = 0
    for path in hook_paths(payload):
        base = Path(cwd).resolve() if isinstance(cwd, str) and cwd else None
        target = path if path.is_absolute() or base is None else base / path
        if not target.is_file():
            continue
        root = base if base is not None and is_within(target.resolve(), base) else target.resolve().parent
        report = scan([target], root=root, fail_on="medium")
        serious = [f for f in report.findings if SEVERITY_RANK[f.severity] >= _MIN_RANK]
        total += len(serious)
        lines.extend(_describe(f) for f in serious[: max(0, MAX_LISTED - len(lines))])
    if not total:
        return None
    header = f"Kestrix found {total} security issue(s) at medium severity or above in the file just written:"
    footer = (
        "Fix these now, keeping behavior the same. If one is a false positive, add "
        "'# kestrix: ignore[<rule-id>] <reason>' on that line or the line above; a suppression without a reason is ignored."
    )
    more = [f"... and {total - len(lines)} more."] if total > len(lines) else []
    context = "\n".join([header, *lines, *more, footer])[:MAX_CONTEXT_CHARS]
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": context}})


def _describe(finding: Finding) -> str:
    return (
        f"- {finding.path}:{finding.line} [{finding.severity.upper()}] {finding.rule_id} ({finding.cwe}): "
        f"{finding.message} Fix: {finding.fix}"
    )
