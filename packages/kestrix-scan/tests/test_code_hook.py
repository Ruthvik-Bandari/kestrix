# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hook mode in-process: only findings the edit introduced, a capped context, and the Stop summary."""

import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from kestrix_scan import hook
from kestrix_scan.models import Finding, TraceStep

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
    assert len(findings) == 2  # twelve os.system calls are one entry, the md5 call another
    assert "[HIGH] py.os.system (CWE-78)" in findings[0] and "— Fix: " in findings[0]
    assert findings[0].endswith("(also at lines 3, 4, 5, 6, 7, 8, 9, 10, ...)")
    assert "py.crypto.weak_hash" in findings[1]
    assert lines[-1] == hook.INSTRUCTION
    assert len(context) <= hook.MAX_CONTEXT_CHARS
    assert all(len(line) <= hook.MAX_LINE_CHARS for line in findings)


def test_many_rules_are_capped_with_a_more_line(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        "import os, subprocess, hashlib, pickle, yaml\nos.system(a)\nsubprocess.run(b, shell=True)\n"
        "hashlib.md5(c)\npickle.loads(d)\nyaml.load(e)\neval(f)\nexec(g)\n"
    )
    context = _context({"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)})
    assert context is not None
    lines = context.splitlines()
    assert len([line for line in lines if line.startswith("- ")]) == hook.MAX_SHOWN
    assert lines[-2].startswith("+") and lines[-2].endswith("more (run /kestrix:scan to list them).")


def test_describe_keeps_the_fix_and_merges_trace_repeats() -> None:
    finding = Finding(
        rule_id="py.x", cwe="CWE-1", severity="high", confidence="high", path="a.py", line=3, column=1, end_line=3,
        message="Long message. " + "word " * 80, why="", fix="Use the safe API instead.", snippet="", fingerprint="f",
        trace=(TraceStep(2, "src"), TraceStep(2, "assign"), TraceStep(3, "sink")),
    )  # fmt: skip
    line = hook.describe(finding)
    assert line.startswith("- a.py:3 [HIGH] py.x (CWE-1): Long message")
    assert line.endswith("— Fix: Use the safe API instead.") and len(line) <= hook.MAX_LINE_CHARS
    short = hook.describe(replace(finding, message="Short"))
    assert "[trace: L2→L3]" in short and "L2→L2" not in short


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


def test_bash_command_reports_the_files_it_changed_against_their_text_before(tmp_path: Path) -> None:
    old, fresh, same = tmp_path / "old.py", tmp_path / "fresh.py", tmp_path / "same.py"
    old.write_text(SHELL + MD5)
    fresh.write_text(SHELL)
    same.write_text(SHELL)
    before = tmp_path / "old.head"
    before.write_text(SHELL)
    kept = tmp_path / "same.head"
    kept.write_text(SHELL)
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "make"},
        "cwd": str(tmp_path),
        "kestrix_files": [str(old), str(fresh), str(same), str(tmp_path / "gone.py")],
        "kestrix_before": {str(old): str(before), str(fresh): None, str(same): str(kept)},
    }
    reply = json.loads(hook.hook_response(json.dumps(payload)) or "{}")
    context = reply["hookSpecificOutput"]["additionalContext"]
    assert context.startswith("Kestrix: this command introduced 2 security issue(s)")
    assert "old.py" in context and "fresh.py" in context and "same.py" not in context
    assert reply["kestrix"] == {"new": 2, "existing": 2}  # the plugin counts these and removes them
    assert hook.hook_response(json.dumps({**payload, "kestrix_files": [str(same)]})) is None


def test_bash_command_scans_at_most_twenty_files(tmp_path: Path) -> None:
    names = []
    for number in range(hook.MAX_BASH_FILES + 3):
        path = tmp_path / f"m{number}.py"
        path.write_text(SHELL)
        names.append(str(path))
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": str(tmp_path), "kestrix_files": names}
    reply = json.loads(hook.hook_response(json.dumps(payload)) or "{}")
    assert reply["kestrix"]["new"] == hook.MAX_BASH_FILES


def test_a_single_finding_keeps_its_explanation_and_fix(tmp_path: Path) -> None:
    """With room to spare, the taint explanation and the whole fix both reach Claude."""
    from kestrix_scan.hook import hook_response

    target = tmp_path / "ping.py"
    target.write_text(
        "import subprocess\nfrom flask import request\n\n\ndef ping():\n"
        '    return subprocess.run("ping -c 2 " + request.args["h"], shell=True)\n'
    )
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "tool_response": {"type": "create"}}
    reply = hook_response(json.dumps({**payload, "cwd": str(tmp_path)}))
    assert reply is not None
    context = json.loads(reply)["hookSpecificOutput"]["additionalContext"]
    assert "request.args" in context and "Fix: Pass the command as a list" in context
    assert "…" not in context


def test_hook_scans_web_files(tmp_path: Path) -> None:
    for name, text, rule in (
        ("App.vue", '<template>\n  <div v-html="body"></div>\n</template>\n', "vue.xss.v_html"),
        ("page.html", '<form action="http://example.com/login"></form>\n', "html.form.http_action"),
        ("Post.svelte", "<p>{@html body}</p>\n", "svelte.xss.at_html"),
    ):
        target = tmp_path / name
        target.write_text(text)
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)}
        context = _context({**payload, "tool_response": {"type": "create"}})
        assert context is not None and rule in context, name


def test_hook_scans_php_and_sql_files(tmp_path: Path) -> None:
    for name, text, rule in (
        ("page.php", "<?php\necho $_GET['q'];\n", "php.xss.echo"),
        ("view.blade.php", "<p>{!! $request->input('q') !!}</p>\n", "php.blade.unescaped"),
        ("init.sql", "GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';\n", "sql.grant.all"),
    ):
        target = tmp_path / name
        target.write_text(text)
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)}
        context = _context({**payload, "tool_response": {"type": "create"}})
        assert context is not None and rule in context, name


def test_hook_context_leaves_out_low_severity_web_findings(tmp_path: Path) -> None:
    target = tmp_path / "site.css"
    target.write_text("@import url(http://example.com/a.css);\n")
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)}
    assert _context({**payload, "tool_response": {"type": "create"}}) is None  # the hook reports medium and above
