# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import time
from pathlib import Path

import pytest
from code_samples import fake, private_key_block
from typer.testing import CliRunner

from kestrix.cli import app as root_app
from kestrix.code import cli, hook, scan

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]
SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"


def invoke(*args: str, stdin: str | None = None):
    return runner.invoke(root_app, ["code", "scan", *args], input=stdin)


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "app.py").write_text(SHELL)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_registered_with_help() -> None:
    (group,) = [group for group in root_app.registered_groups if group.name == "code"]
    assert group.help == "Find security issues in source code (exits non-zero on findings)."
    assert runner.invoke(root_app, ["code", "--help"]).exit_code == 0


def test_text_output_and_exit_1(project: Path) -> None:
    result = invoke()
    assert result.exit_code == 1
    assert "app.py\n  4:5  HIGH  py.subprocess.shell_true  CWE-78" in result.stdout
    assert "fix: Pass the command as a list" in result.stdout
    assert "1 finding(s): 0 critical, 1 high, 0 medium, 0 low in 1 file(s)" in result.stdout
    assert "\x1b[" not in result.stdout  # no color when stdout is not a terminal


def test_color_only_on_a_terminal(project: Path) -> None:
    report = scan(["."])
    assert "\x1b[" in cli.render_text(report, color=True)
    assert "\x1b[" not in cli.render_text(report, color=False)


def test_clean_scan_exits_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "ok.py").write_text("print('hi')\n")
    monkeypatch.chdir(tmp_path)
    result = invoke()
    assert result.exit_code == 0 and "No findings." in result.stdout


@pytest.mark.parametrize(("fail_on", "code"), [("critical", 0), ("high", 1), ("low", 1), ("none", 0)])
def test_fail_on(project: Path, fail_on: str, code: int) -> None:
    assert invoke("--fail-on", fail_on).exit_code == code


def test_json_and_sarif_formats(project: Path) -> None:
    report = json.loads(invoke("--format", "json").stdout)
    assert report["findings"][0]["rule_id"] == "py.subprocess.shell_true" and report["fail_on"] == "high"
    sarif = json.loads(invoke("--format", "sarif").stdout)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "py.subprocess.shell_true"


def test_output_file(project: Path) -> None:
    result = invoke("--format", "json", "--output", "report.json")
    assert result.exit_code == 1 and result.stdout == ""
    assert json.loads((project / "report.json").read_text())["counts"]["high"] == 1


def test_usage_errors_exit_2(project: Path) -> None:
    missing = invoke("nope")
    assert missing.exit_code == 2 and "Rejected (invalid_input): path not found: nope" in missing.output
    (project / "bad.json").write_text("{")
    assert invoke("--baseline", "bad.json").exit_code == 2
    diff = invoke("--diff", "main")
    assert diff.exit_code == 2 and "not inside a git work tree" in diff.output
    assert invoke("--format", "xml").exit_code == 2


def test_write_baseline_then_use_it(project: Path) -> None:
    written = invoke("--write-baseline", "kestrix-baseline.json")
    assert written.exit_code == 0 and "Wrote 1 fingerprint(s)" in written.output
    result = invoke("--baseline", "kestrix-baseline.json")
    assert result.exit_code == 0 and "1 in baseline" in result.stdout


# ----- secrets never appear in any output


def test_secret_values_never_reach_any_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    kinds = ["github_token", "stripe_live_key", "anthropic_api_key", "aws_access_key_id", "jwt", "generic"]
    values = [fake(kind) for kind in kinds]
    lines = [
        f"value_{i} = '{v}'" if kind != "generic" else f"db_password = '{v}'"
        for i, (kind, v) in enumerate(zip(kinds, values, strict=True))
    ]
    source = "import os\n" + "\n".join(lines) + f"\nos.system(x + '{values[0]}')\n"
    (tmp_path / "leaky.py").write_text(source)
    (tmp_path / "id_rsa.txt").write_text(private_key_block())
    key_body = private_key_block().splitlines()[1]
    monkeypatch.chdir(tmp_path)
    outputs = []
    for fmt in ("text", "json", "sarif"):
        result = invoke("--format", fmt, "--fail-on", "none")
        assert result.exit_code == 0
        outputs.append(result.output)
    assert invoke("--write-baseline", "b.json").exit_code == 0
    outputs.append((tmp_path / "b.json").read_text())
    payload = json.dumps(
        {"tool_name": "Write", "tool_input": {"file_path": str(tmp_path / "leaky.py")}, "cwd": str(tmp_path)}
    )
    hook_result = invoke("--hook", stdin=payload)
    assert "secret." in hook_result.stdout
    outputs.append(hook_result.output)
    assert json.loads(outputs[1])["counts"]["critical"] >= 4
    for output in outputs:
        for value in [*values, key_body]:
            assert value not in output
            assert value[6:30] not in output


# ----- hook mode


def hook_payload(path: Path, tool: str = "Write", **extra: object) -> str:
    return json.dumps({"tool_name": tool, "tool_input": {"file_path": str(path), **extra}, "cwd": str(path.parent)})


def test_hook_reports_findings(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(SHELL)
    result = invoke("--hook", stdin=hook_payload(path))
    assert result.exit_code == 0
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "PostToolUse"
    context = output["additionalContext"]
    assert "app.py:4 [HIGH] py.subprocess.shell_true (CWE-78)" in context
    assert "Fix:" in context and "kestrix: ignore[" in context


def test_hook_multiedit_edits_paths(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(SHELL)
    payload = json.dumps({"tool_name": "MultiEdit", "tool_input": {"edits": [{"file_path": str(path)}]}})
    assert "py.subprocess.shell_true" in invoke("--hook", stdin=payload).stdout


def test_hook_notebook_edit_uses_notebook_path(tmp_path: Path) -> None:
    path = tmp_path / "analysis.ipynb"
    path.write_text(json.dumps({"cells": [{"source": [f"GITHUB_TOKEN = '{fake('github_token')}'\n"]}]}))
    payload = json.dumps({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": str(path), "new_source": "x"}})
    assert "secret.github_token" in invoke("--hook", stdin=payload).stdout


def test_hook_is_silent_without_medium_findings(tmp_path: Path) -> None:
    path = tmp_path / "ok.py"
    path.write_text("import hashlib\nh = hashlib.md5(b'', usedforsecurity=False)\n")  # low only
    result = invoke("--hook", stdin=hook_payload(path))
    assert result.exit_code == 0 and result.stdout == ""


@pytest.mark.parametrize(
    "stdin", ["not json", "[]", '{"tool_input": 3}', '{"tool_input": {"file_path": "/no/such/file.py"}}', ""]
)
def test_hook_fails_open_on_bad_input(stdin: str) -> None:
    result = invoke("--hook", stdin=stdin)
    assert result.exit_code == 0 and result.stdout == ""


def test_hook_fails_open_on_scanner_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "app.py"
    path.write_text(SHELL)

    def broken(*_: object, **__: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(hook, "scan", broken)
    result = invoke("--hook", stdin=hook_payload(path))
    assert result.exit_code == 0 and result.stdout == ""
    assert "skipped (RuntimeError)" in result.output


def test_hook_relative_path_uses_cwd(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SHELL)
    payload = json.dumps({"tool_input": {"file_path": "app.py"}, "cwd": str(tmp_path)})
    assert "app.py:4" in invoke("--hook", stdin=payload).stdout


def test_hook_is_fast_on_a_2000_line_file(tmp_path: Path) -> None:
    body = "".join(
        f"def handler_{i}(cursor, value, path):\n"
        f"    query = 'SELECT name FROM items WHERE id = ?'\n"
        f"    cursor.execute(query, (value,))\n"
        f"    return [str(x) + path for x in range({i % 7})]\n\n"
        for i in range(400)
    )
    path = tmp_path / "big.py"
    path.write_text("import os\n" + body + "os.system(path)\n")
    assert len(path.read_text().splitlines()) >= 2000
    started = time.perf_counter()
    result = invoke("--hook", stdin=hook_payload(path))
    elapsed = time.perf_counter() - started
    assert "py.os.system" in result.stdout
    assert elapsed < 1.5


# ----- this repository


def test_self_scan_has_no_high_or_critical_findings() -> None:
    report = scan([REPO / "src"], root=REPO)
    serious = [(f.path, f.line, f.rule_id) for f in report.findings if f.severity in {"high", "critical"}]
    assert serious == []
    assert report.files_scanned > 50 and report.notes == []
