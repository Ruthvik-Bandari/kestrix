# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The plugin's hook script, run the way Claude Code runs it: a subprocess with the hook JSON on stdin."""

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "src" / "kestrix" / "integrations" / "claude_plugin" / "kestrix"
SCRIPT = PLUGIN / "hooks" / "kestrix_hook.py"
KESTRIX = shutil.which("kestrix", path=str(Path(sys.executable).parent))
VULNERABLE = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
SAFE = "import subprocess\n\ndef run(args):\n    subprocess.run(args, check=True)\n"

EVENTS = {"SessionStart": "session-start", "PostToolUse": "post-tool-use", "Stop": "stop"}

pytestmark = pytest.mark.skipif(KESTRIX is None, reason="needs the kestrix entry point next to the interpreter")


class Hooks:
    """One Claude Code session: its own session id, project directory and plugin data directory."""

    def __init__(self, root: Path, *, kestrix_on_path: bool = True) -> None:
        self.project = root / "project"
        self.project.mkdir()
        self.data = root / "plugin-data"
        bin_dir = Path(KESTRIX).parent if kestrix_on_path and KESTRIX else root / "empty-bin"
        bin_dir.mkdir(exist_ok=True)
        self.env = {
            "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
            "HOME": str(root),
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
            "CLAUDE_PLUGIN_DATA": str(self.data),
        }
        self.session = "session-1"

    def run(self, event: str, payload: dict[str, Any], **env: str) -> subprocess.CompletedProcess[str]:
        body = {"session_id": self.session, "cwd": str(self.project), "hook_event_name": event, **payload}
        return subprocess.run(
            [sys.executable, str(SCRIPT), EVENTS[event]],
            input=json.dumps(body),
            capture_output=True,
            text=True,
            cwd=self.project,
            env={**self.env, **env},
            timeout=60,
            check=False,
        )

    def write(self, name: str, source: str, tool: str = "Write") -> subprocess.CompletedProcess[str]:
        path = self.project / name
        path.write_text(source)
        return self.run(
            "PostToolUse",
            {
                "tool_name": tool,
                "tool_input": {"file_path": str(path), "content": source},
                "tool_response": {"filePath": str(path), "type": "create"},
                "tool_use_id": "toolu_1",
            },
        )

    def stop(self, *, active: bool = False, **env: str) -> subprocess.CompletedProcess[str]:
        return self.run("Stop", {"stop_hook_active": active, "last_assistant_message": "Done."}, **env)


@pytest.fixture
def hooks(tmp_path: Path) -> Hooks:
    return Hooks(tmp_path)


def test_script_runs_on_python_3_9() -> None:
    ast.parse(SCRIPT.read_text(encoding="utf-8"), feature_version=(3, 9))


def test_post_tool_use_reports_the_rule(hooks: Hooks) -> None:
    result = hooks.write("app.py", VULNERABLE)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "PostToolUse"
    assert "py.subprocess.shell_true" in output["additionalContext"]
    assert "Fix these now" in output["additionalContext"]
    assert "confirmed false positive" in output["additionalContext"]


def test_post_tool_use_relative_and_multiedit_paths(hooks: Hooks) -> None:
    (hooks.project / "app.py").write_text(VULNERABLE)
    result = hooks.run("PostToolUse", {"tool_name": "MultiEdit", "tool_input": {"edits": [{"file_path": "app.py"}]}})
    assert "py.subprocess.shell_true" in result.stdout
    assert (hooks.data / "sessions" / hooks.session / "changed.txt").read_text() == f"{hooks.project / 'app.py'}\n"


def test_safe_file_produces_no_output(hooks: Hooks) -> None:
    result = hooks.write("app.py", SAFE)
    assert (result.returncode, result.stdout) == (0, "")


def test_missing_kestrix_fails_open_with_one_hint(tmp_path: Path) -> None:
    hooks = Hooks(tmp_path, kestrix_on_path=False)
    first = hooks.write("app.py", VULNERABLE)
    assert first.returncode == 0
    reply = json.loads(first.stdout)
    assert "not on PATH" in reply["systemMessage"]
    assert "do not install it yourself" in reply["hookSpecificOutput"]["additionalContext"]
    second = hooks.write("other.py", VULNERABLE)
    assert (second.returncode, second.stdout) == (0, "")
    assert hooks.run("SessionStart", {"source": "startup"}).stdout == ""
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout == ""


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"tool_input": "x"}'])
def test_bad_input_fails_open(hooks: Hooks, stdin: str) -> None:
    events = (
        ("post-tool-use", "stop", "unknown") if stdin.startswith("{") else ("post-tool-use", "stop", "session-start")
    )
    for event in events:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), event],
            input=stdin,
            capture_output=True,
            text=True,
            env=hooks.env,
            check=False,
        )
        assert (result.returncode, result.stdout) == (0, "")


def test_session_start_announces_the_hooks(hooks: Hooks) -> None:
    result = hooks.run("SessionStart", {"source": "startup"})
    context = json.loads(result.stdout)["hookSpecificOutput"]
    assert context["hookEventName"] == "SessionStart"
    assert context["additionalContext"].startswith("Kestrix security hooks are active")
    assert "\n" not in context["additionalContext"]
    assert "Stop gate off" in context["additionalContext"]
    assert "Stop gate on" in hooks.run("SessionStart", {"source": "startup"}, KESTRIX_BLOCK_ON_STOP="1").stdout


def test_stop_gate_is_off_unless_enabled(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    assert hooks.stop().stdout == ""


def test_stop_gate_blocks_with_the_findings(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    hooks.write("ok.py", SAFE)
    result = hooks.stop(KESTRIX_BLOCK_ON_STOP="1")
    assert result.returncode == 0, result.stderr
    reply = json.loads(result.stdout)
    assert reply["decision"] == "block"
    assert f"{hooks.project / 'app.py'}:4 [HIGH] py.subprocess.shell_true (CWE-78)" in reply["reason"]
    assert "ok.py" not in reply["reason"]
    assert "block 1 of 3" in reply["reason"]


def test_stop_gate_respects_stop_hook_active(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    assert hooks.stop(active=True, KESTRIX_BLOCK_ON_STOP="1").stdout == ""


def test_stop_gate_project_file_and_env_override(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    (hooks.project / ".kestrix.json").write_text(json.dumps({"claude": {"block_on_stop": True}}))
    assert json.loads(hooks.stop().stdout)["decision"] == "block"
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="0").stdout == ""
    (hooks.project / ".kestrix.json").write_text(json.dumps({"claude": {"block_on_stop": "yes"}}))
    assert hooks.stop().stdout == ""
    (hooks.project / ".kestrix.json").write_text("{broken")
    assert hooks.stop().returncode == 0


def test_stop_gate_allows_stop_once_fixed(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout
    hooks.write("app.py", SAFE)
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout == ""
    hooks.write(
        "app.py",
        VULNERABLE.replace("shell=True)", "shell=True)  # kestrix: ignore[py.subprocess.shell_true] fixed command"),
    )
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout == ""


def test_stop_gate_caps_blocks_per_session(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    replies = [hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout for _ in range(5)]
    assert [json.loads(r).get("decision") for r in replies[:3]] == ["block"] * 3
    assert "block 3 of 3" in replies[2]
    assert "already blocked 3 times" in json.loads(replies[3])["systemMessage"]
    assert replies[4] == ""
    hooks.session = "session-2"  # a new session starts with a fresh budget and file list
    hooks.write("app.py", VULNERABLE)
    assert json.loads(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)["decision"] == "block"


def test_session_state_falls_back_to_a_private_temp_dir(hooks: Hooks, tmp_path: Path) -> None:
    env = {k: v for k, v in hooks.env.items() if k != "CLAUDE_PLUGIN_DATA"}
    hooks.env = {**env, "TMPDIR": str(tmp_path)}
    hooks.session = "../../escape"
    hooks.write("app.py", VULNERABLE)
    base = tmp_path / f"kestrix-claude-{os.getuid()}"
    assert base.stat().st_mode & 0o777 == 0o700
    (session_dir,) = (base / "sessions").iterdir()
    assert len(session_dir.name) == 32 and (session_dir / "changed.txt").is_file()
    assert json.loads(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)["decision"] == "block"


# ----- in-process checks of the timeout and scanner-error paths


@pytest.fixture
def module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # keep __pycache__ out of the packaged plugin
    spec = importlib.util.spec_from_file_location("kestrix_hook", SCRIPT)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def _fake_kestrix(tmp_path: Path, body: str) -> Path:
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    exe = bin_dir / "kestrix"
    exe.write_text(f"#!/bin/sh\n{body}\n")
    exe.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize("body", ["sleep 5", "echo not-json", "exit 3", "echo '{\"other\": 1}'"])
def test_scanner_problems_fail_open(
    module: ModuleType, body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PATH", str(_fake_kestrix(tmp_path, body)))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setattr(module, "SCAN_TIMEOUT_S", 0.5)
    target = tmp_path / "app.py"
    target.write_text(VULNERABLE)
    payload = {"session_id": "s", "cwd": str(tmp_path), "tool_input": {"file_path": str(target)}}
    module.post_tool_use(json.dumps(payload).encode(), payload)
    assert capsys.readouterr().out == ""


def test_kestrix_in_the_project_directory_is_not_trusted(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = _fake_kestrix(tmp_path, "exit 0")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.chdir(bin_dir)
    assert module._kestrix() is None
    monkeypatch.chdir(tmp_path)
    assert module._kestrix() == str(bin_dir / "kestrix")
