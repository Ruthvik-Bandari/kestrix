# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hook mode in-process: only findings the edit introduced, a capped context, and the Stop summary."""

import json
import time
from pathlib import Path
from typing import Any

from kestrix.code import hook

SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
MD5 = "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"


def _context(payload: dict[str, Any]) -> str | None:
    reply = hook.hook_response(json.dumps(payload))
    return None if reply is None else str(json.loads(reply)["hookSpecificOutput"]["additionalContext"])


def test_undo_edits_reverses_unique_replacements() -> None:
    edits = [{"old_string": "a = 1", "new_string": "a = 2"}, {"old_string": "b = 1", "new_string": "b = 3"}]
    assert hook.undo_edits("a = 2\nb = 3\n", edits) == "a = 1\nb = 1\n"
    assert hook.undo_edits("x\nx\n", [{"old_string": "y", "new_string": "x"}]) is None  # ambiguous
    assert hook.undo_edits("x\n", [{"old_string": "y", "new_string": ""}]) is None  # deletion: nowhere to anchor
    assert hook.undo_edits("x\n", ["not an edit"]) is None


def test_before_text_sources(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(SHELL + MD5)
    snapshot = tmp_path / "snap"
    snapshot.write_text(SHELL)
    key = str(target)
    assert hook.before_text({"kestrix_before": {key: str(snapshot)}}, target) == SHELL
    assert hook.before_text({"kestrix_before": {key: None}}, target) == ""
    write = {"tool_name": "Write", "tool_input": {"file_path": key}}
    assert hook.before_text({**write, "tool_response": {"type": "create"}}, target) == ""
    assert hook.before_text({**write, "tool_response": {"type": "update"}}, target) is None
    edit = {"tool_name": "Edit", "tool_input": {"file_path": key, "old_string": "", "new_string": MD5}}
    assert hook.before_text(edit, target) == SHELL
    multi = {"tool_name": "MultiEdit", "tool_input": {"file_path": key, "edits": [edit["tool_input"]]}}
    assert hook.before_text(multi, target) == SHELL
    assert hook.before_text({"tool_name": "NotebookEdit", "tool_input": {}}, target) is None


def test_only_introduced_findings_are_reported(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(MD5 + SHELL)
    edit = {"file_path": str(target), "old_string": "", "new_string": SHELL}
    context = _context({"tool_name": "Edit", "tool_input": edit, "cwd": str(tmp_path)})
    assert context is not None
    assert "py.subprocess.shell_true" in context and "py.crypto.weak_hash" not in context
    assert "1 existing issue(s) in this file were already there" in context
    unchanged = {"tool_name": "Edit", "tool_input": {**edit, "new_string": MD5, "old_string": MD5}}
    target.write_text(MD5)
    assert _context({**unchanged, "cwd": str(tmp_path)}) is None


def test_moved_code_keeps_its_fingerprint(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("\n\n\n" + SHELL)  # the same finding, three lines lower
    snapshot = tmp_path / "before.txt"
    snapshot.write_text(SHELL)
    payload = {"tool_input": {"file_path": str(target)}, "kestrix_before": {str(target): str(snapshot)}}
    assert _context({**payload, "cwd": str(tmp_path)}) is None


def test_context_is_capped_and_structured(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    calls = "".join(f"os.system(cmd{i})\n" for i in range(12))
    target.write_text("import os, hashlib\n" + calls + "h = hashlib.md5(cmd)\n")
    context = _context({"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)})
    assert context is not None
    lines = context.splitlines()
    assert lines[0] == "Kestrix: this edit introduced 13 security issue(s) at medium severity or above:"
    findings = [line for line in lines if line.startswith("- ")]
    assert len(findings) == hook.MAX_SHOWN
    assert all("[HIGH] py.os.system (CWE-78)" in line and "— Fix: " in line for line in findings)
    assert lines[-2] == "+8 more (run /kestrix:scan to list them)."
    assert lines[-1] == hook.INSTRUCTION
    assert len(context) <= hook.MAX_CONTEXT_CHARS
    assert all(len(line) <= hook.MAX_LINE_CHARS for line in findings)


def test_stop_summary_lists_new_high_findings(tmp_path: Path) -> None:
    old, fresh = tmp_path / "old.py", tmp_path / "fresh.py"
    old.write_text(SHELL + MD5)
    fresh.write_text(SHELL)
    snapshot = tmp_path / "old.snap"
    snapshot.write_text(SHELL)
    payload = {
        "hook_event_name": "Stop",
        "cwd": str(tmp_path),
        "kestrix_files": [str(old), str(fresh), str(tmp_path / "gone.py")],
        "kestrix_before": {str(old): str(snapshot), str(fresh): None},
    }
    reply = json.loads(hook.hook_response(json.dumps(payload)) or "{}")["kestrix_stop"]
    assert [item["line"].split(" ")[1] for item in reply["new"]] == ["fresh.py:4"]  # md5 is medium, not listed
    assert reply["existing"] == 1 and len(reply["new"][0]["fingerprint"]) == 64


def test_hook_scan_of_a_2000_line_file_is_fast(tmp_path: Path) -> None:
    body = "".join(
        f"def handler_{i}(cursor, value):\n    cursor.execute('SELECT name FROM t WHERE id = ?', (value,))\n"
        f"    return value\n\n"
        for i in range(500)
    )
    target = tmp_path / "big.py"
    target.write_text("import os\n" + body + "os.system(value)\n")
    assert len(target.read_text().splitlines()) >= 2000
    payload = {"tool_name": "Edit", "tool_input": {"file_path": str(target), "old_string": "", "new_string": "x"}}
    started = time.perf_counter()
    hook.hook_response(json.dumps({**payload, "cwd": str(tmp_path)}))
    assert time.perf_counter() - started < 2.0  # generous: measured p95 is far lower (docs/claude-plugin.md)
