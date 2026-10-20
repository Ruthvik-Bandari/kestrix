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
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

PLUGIN = Path(__file__).resolve().parents[1] / "src" / "kestrix_scan" / "claude_plugin" / "kestrix"
SCRIPT = PLUGIN / "hooks" / "kestrix_hook.py"
KESTRIX = shutil.which("kestrix-scan", path=str(Path(sys.executable).parent))
VULNERABLE = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
SAFE = "import subprocess\n\ndef run(args):\n    subprocess.run(args, check=True)\n"

EVENTS = {"SessionStart": "session-start", "PreToolUse": "pre-tool-use", "PostToolUse": "post-tool-use", "Stop": "stop"}

pytestmark = pytest.mark.skipif(KESTRIX is None, reason="needs the kestrix-scan entry point next to the interpreter")


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
        self.snapshots = True

    def run(
        self, event: str, payload: dict[str, Any], *, arg: str | None = None, **env: str
    ) -> subprocess.CompletedProcess[str]:
        body = {"session_id": self.session, "cwd": str(self.project), "hook_event_name": event, **payload}
        return subprocess.run(
            [sys.executable, str(SCRIPT), arg or EVENTS[event]],
            input=json.dumps(body),
            capture_output=True,
            text=True,
            cwd=self.project,
            env={**self.env, **env},
            timeout=60,
            check=False,
        )

    def write(self, name: str, source: str, tool: str = "Write") -> subprocess.CompletedProcess[str]:
        """PreToolUse, the write itself, then PostToolUse, as Claude Code runs them."""
        path = self.project / name
        existed = path.exists()
        tool_input = {"file_path": str(path), "content": source}
        pre = self.run("PreToolUse", {"tool_name": tool, "tool_input": tool_input, "tool_use_id": "toolu_1"})
        assert (pre.returncode, pre.stdout) == (0, "")
        path.write_text(source)
        return self.run(
            "PostToolUse",
            {
                "tool_name": tool,
                "tool_input": tool_input,
                "tool_response": {"filePath": str(path), "type": "update" if existed else "create"},
                "tool_use_id": "toolu_1",
            },
        )

    def edit(self, name: str, old: str, new: str) -> subprocess.CompletedProcess[str]:
        """An Edit with or without the PreToolUse snapshot (``self.snapshots``)."""
        path = self.project / name
        tool_input = {"file_path": str(path), "old_string": old, "new_string": new, "replace_all": False}
        if self.snapshots:
            self.run("PreToolUse", {"tool_name": "Edit", "tool_input": tool_input, "tool_use_id": "toolu_2"})
        path.write_text(path.read_text().replace(old, new, 1))
        return self.run(
            "PostToolUse",
            {
                "tool_name": "Edit",
                "tool_input": tool_input,
                "tool_response": {"filePath": str(path)},
                "tool_use_id": "toolu_2",
            },
        )

    def bash(
        self, effect: Callable[[], None], *, failure: bool = False, command: str = "make", call: str = "toolu_b1"
    ) -> subprocess.CompletedProcess[str]:
        """PreToolUse on Bash, the command's effect on the files, then PostToolUse (or PostToolUseFailure)."""
        tool = {"tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": call}
        pre = self.run("PreToolUse", tool, arg="install-guard")
        assert (pre.returncode, pre.stdout) == (0, "")
        effect()
        event = "PostToolUseFailure" if failure else "PostToolUse"
        response = {"error": "Exit code 1"} if failure else {"tool_response": {"stdout": "", "stderr": ""}}
        return self.run(event, {**tool, **response}, arg="bash-post")

    def status(self) -> str:
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "status", self.session, str(self.data)],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        return done.stdout

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
    assert "this edit introduced 1 security issue(s)" in output["additionalContext"]
    assert output["additionalContext"].splitlines()[-1].startswith("Fix the new issues now")
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
    assert "neither kestrix-scan nor kestrix is on PATH" in reply["systemMessage"]
    assert "install the kestrix-scan package from PyPI" in reply["systemMessage"]
    assert "pip install" not in first.stdout  # the hint names no command line: the hooks never install
    assert "do not install it yourself" in reply["hookSpecificOutput"]["additionalContext"]
    second = json.loads(hooks.write("other.py", VULNERABLE).stdout)
    assert "systemMessage" not in second  # the user hears it once; Claude is told about every unchecked file
    assert "NOT security-check" in second["hookSpecificOutput"]["additionalContext"]
    assert "other.py" in second["hookSpecificOutput"]["additionalContext"]
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
    assert "- app.py:4 [HIGH] py.subprocess.shell_true (CWE-78)" in reply["reason"]
    assert "ok.py" not in reply["reason"]
    assert "block 1 of 3" in reply["reason"]
    assert "1 new high or critical finding(s)" in reply["systemMessage"]


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
    replies = []
    for number in range(5):  # different findings each time, so only the cap stops the blocks
        hooks.write(f"app{number}.py", VULNERABLE)
        replies.append(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)
    assert [json.loads(r).get("decision") for r in replies[:3]] == ["block"] * 3
    assert "block 3 of 3" in replies[2]
    assert "already blocked 3 times" in json.loads(replies[3])["systemMessage"]
    assert "decision" not in json.loads(replies[3])
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


# ----- only what this session introduced

MD5 = "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"


def _context(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, result.stderr
    return str(json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"])


def test_pre_tool_use_snapshots_silently(hooks: Hooks) -> None:
    (hooks.project / "app.py").write_text(VULNERABLE)
    tool_input = {"file_path": str(hooks.project / "app.py"), "content": SAFE}
    result = hooks.run("PreToolUse", {"tool_name": "Write", "tool_input": tool_input})
    assert (result.returncode, result.stdout) == (0, "")
    state = hooks.data / "sessions" / hooks.session
    (first,) = (state / "before-first").iterdir()
    (prev,) = (state / "before-prev").iterdir()
    assert first.read_text() == prev.read_text() == VULNERABLE
    hooks.run("PreToolUse", {"tool_name": "Write", "tool_input": {**tool_input, "file_path": "new.py"}})
    assert len(list((state / "before-first").glob("*.absent"))) == 1


def test_edit_reports_only_new_findings(hooks: Hooks) -> None:
    (hooks.project / "app.py").write_text(VULNERABLE + MD5)
    unrelated = hooks.edit("app.py", "def digest(data):", "def digest(data: bytes):")
    assert (unrelated.returncode, unrelated.stdout) == (0, "")
    context = _context(
        hooks.edit(
            "app.py",
            "def digest(data: bytes):",
            "def digest(data: bytes, cmd=''):\n    os_cmd = cmd\n    import os; os.system(os_cmd)\n   ",
        )
    )
    assert "py.os.system" in context
    assert "py.subprocess.shell_true" not in context and "py.crypto.weak_hash" not in context
    assert "2 existing issue(s) in this file were already there (run /kestrix:scan)." in context
    assert not list((hooks.data / "sessions" / hooks.session / "before-prev").iterdir())  # consumed


def test_edit_without_a_snapshot_is_undone_from_the_tool_input(hooks: Hooks) -> None:
    hooks.snapshots = False
    (hooks.project / "app.py").write_text(VULNERABLE)
    assert hooks.edit("app.py", "def run(cmd):", "def run(cmd, check=False):").stdout == ""
    assert "py.crypto.weak_hash" in _context(
        hooks.edit("app.py", "import subprocess", "import subprocess\nimport hashlib\nH = hashlib.md5(b'x')")
    )


def test_write_over_an_existing_file_compares_with_the_snapshot(hooks: Hooks) -> None:
    (hooks.project / "app.py").write_text(VULNERABLE)
    assert hooks.write("app.py", VULNERABLE + "\nVERSION = 2\n").stdout == ""
    context = _context(hooks.write("app.py", VULNERABLE + MD5))
    assert "py.crypto.weak_hash" in context and "1 existing issue(s)" in context


def test_stop_gate_ignores_findings_that_were_there_before_the_session(hooks: Hooks) -> None:
    (hooks.project / "legacy.py").write_text(VULNERABLE)
    hooks.write("legacy.py", VULNERABLE + "\nVERSION = 2\n")
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout == ""
    hooks.write("legacy.py", VULNERABLE + "\nimport os\nos.system(input())\n")
    reply = json.loads(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)
    assert "py.os.system" in reply["reason"] and "py.subprocess.shell_true" not in reply["reason"]


def test_stop_gate_warns_instead_when_the_same_findings_persist(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    first, second, third, fourth = (hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout for _ in range(4))
    assert json.loads(first)["decision"] == json.loads(second)["decision"] == "block"
    reply = json.loads(third)
    assert "decision" not in reply
    assert "same 1 high or critical finding(s) remain after 2 blocks" in reply["systemMessage"]
    assert fourth == ""
    hooks.write("other.py", VULNERABLE)  # new findings may still use the last block
    assert "block 3 of 3" in json.loads(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)["reason"]


def test_stop_gate_fails_open_on_an_internal_error(hooks: Hooks) -> None:
    hooks.write("app.py", VULNERABLE)
    state = hooks.data / "sessions" / hooks.session
    (state / "stop-blocks").mkdir()  # reading and writing the block count now fails
    result = hooks.stop(KESTRIX_BLOCK_ON_STOP="1")
    assert (result.returncode, result.stdout) == (0, "")
    assert "kestrix hook stop: skipped" in result.stderr


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


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("/bin/sleep 5", "timed out after"),
        ("echo not-json", "failed with unreadable output"),
        ("exit 3", "failed with exit code 3"),
        ('echo \'{"kestrix_error": "OSError"}\'', "failed with an internal error (OSError)"),
        ("echo '{\"other\": 1}'", None),  # valid JSON without findings is a clean scan
    ],
)
def test_scanner_problems_fail_open_and_are_visible(
    module: ModuleType,
    body: str,
    reason: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PATH", str(_fake_kestrix(tmp_path, body)))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setattr(module, "SCAN_TIMEOUT_S", 0.5)
    target = tmp_path / "app.py"
    target.write_text(VULNERABLE)
    payload = {"session_id": "s", "cwd": str(tmp_path), "tool_input": {"file_path": str(target)}}
    module.post_tool_use(json.dumps(payload).encode(), payload)
    out = capsys.readouterr().out
    if reason is None:
        assert out == ""
        return
    reply = json.loads(out)
    assert reason in reply["systemMessage"] and "was not security-checked" in reply["systemMessage"]
    context = reply["hookSpecificOutput"]["additionalContext"]
    assert "could NOT security-check" in context and reason in context and "\n" not in context


def test_kestrix_in_the_project_directory_is_not_trusted(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = _fake_kestrix(tmp_path, "exit 0")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.chdir(bin_dir)
    assert module._kestrix() is None
    monkeypatch.chdir(tmp_path)
    assert module._kestrix() == str(bin_dir / "kestrix")


def _fake(bin_dir: Path, name: str, body: str) -> Path:
    bin_dir.mkdir(exist_ok=True)
    exe = bin_dir / name
    exe.write_text(f"#!/bin/sh\n{body}\n")
    exe.chmod(0o755)
    return exe


def test_kestrix_scan_is_preferred_and_kestrix_code_scan_is_the_fallback(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    scanner = _fake(bin_dir, "kestrix-scan", "exit 0")
    kestrix = _fake(bin_dir, "kestrix", "exit 0")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.chdir(tmp_path)
    assert module._scanner() == [str(scanner), "scan"]
    scanner.unlink()
    assert module._scanner() == [str(kestrix), "code", "scan"]
    kestrix.unlink()
    assert module._scanner() is None


def test_kestrix_scan_in_the_project_directory_is_not_trusted(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    _fake(bin_dir, "kestrix-scan", "exit 0")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.chdir(bin_dir)
    assert module._scanner() is None


def test_post_tool_use_runs_kestrix_scan_with_the_hook_flag(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = tmp_path / "calls.txt"
    _fake(tmp_path / "bin", "kestrix-scan", f'echo "$@" >> "{calls}"')
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    target = tmp_path / "app.py"
    target.write_text(VULNERABLE)
    payload = {"session_id": "s", "cwd": str(tmp_path), "tool_input": {"file_path": str(target)}}
    module.post_tool_use(json.dumps(payload).encode(), payload)
    assert calls.read_text() == "scan --hook\n"
    assert capsys.readouterr().out == ""


# ----- three visible scan states: clean, findings, unavailable


def _fake_scanner(bin_dir: Path, body: str) -> None:
    exe = bin_dir / "kestrix-scan"
    exe.write_text(f"#!/bin/sh\n{body}\n")
    exe.chmod(0o755)


def test_clean_scan_is_silent_and_counted(hooks: Hooks) -> None:
    assert hooks.write("ok.py", SAFE).stdout == ""
    status = hooks.status()
    assert "Scans completed: 1, covering 1 file(s)." in status
    assert "NOT security-checked: nothing." in status


def test_findings_are_reported_and_counted(hooks: Hooks) -> None:
    context = _context(hooks.write("app.py", VULNERABLE + MD5))
    assert "this edit introduced 2 security issue(s)" in context
    assert "kestrix" not in json.loads(hooks.write("again.py", VULNERABLE).stdout)  # counts never reach Claude Code
    status = hooks.status()
    assert "Scans completed: 2, covering 2 file(s)." in status
    assert "Findings reported to Claude: 3 new" in status


@pytest.mark.parametrize(
    ("cause", "scanner", "fragment"),
    [
        ("missing", None, "neither kestrix-scan nor kestrix is on PATH"),
        ("error", "exit 3", "failed with exit code 3"),
    ],
)
def test_unavailable_scan_is_visible_once_per_cause_and_counted(
    tmp_path: Path, cause: str, scanner: str | None, fragment: str
) -> None:
    hooks = Hooks(tmp_path, kestrix_on_path=False)
    if scanner is not None:
        _fake_scanner(tmp_path / "empty-bin", scanner)
    first = json.loads(hooks.write("a.py", VULNERABLE).stdout)
    assert fragment in first["systemMessage"]
    assert "a.py" in first["hookSpecificOutput"]["additionalContext"]
    assert "NOT security-check" in first["hookSpecificOutput"]["additionalContext"]
    second = json.loads(hooks.write("b.py", VULNERABLE).stdout)
    assert "systemMessage" not in second
    assert "b.py" in second["hookSpecificOutput"]["additionalContext"]
    status = hooks.status()
    assert f"NOT security-checked: 2 time(s) (2 {cause})." in status
    listed = [line for line in status.splitlines() if line.startswith("  - ")]
    assert [line.rsplit("/", 1)[-1] for line in listed] == ["a.py", "b.py"]


def test_each_cause_gets_its_own_message(tmp_path: Path) -> None:
    hooks = Hooks(tmp_path, kestrix_on_path=False)
    bin_dir = tmp_path / "empty-bin"
    assert "systemMessage" in json.loads(hooks.write("a.py", VULNERABLE).stdout)  # missing
    _fake_scanner(bin_dir, "exit 3")
    assert "failed with exit code 3" in json.loads(hooks.write("b.py", VULNERABLE).stdout)["systemMessage"]
    assert "systemMessage" not in json.loads(hooks.write("c.py", VULNERABLE).stdout)
    _fake_scanner(bin_dir, 'echo \'{"kestrix_error": "ValueError"}\'')
    assert "systemMessage" not in json.loads(hooks.write("d.py", VULNERABLE).stdout)  # still the error cause
    status = hooks.status()
    assert "1 missing" in status and "3 error" in status


def test_a_crash_inside_the_real_scanner_is_unavailable_not_clean(hooks: Hooks) -> None:
    (hooks.project / "app.py").write_text(VULNERABLE)
    tool_input = {"file_path": str(hooks.project / "app.py")}
    stub = hooks.project.parent / "crash-bin"
    stub.mkdir()
    _fake_scanner(
        stub, "echo 'kestrix-scan --hook: skipped (RecursionError)' >&2\necho '{\"kestrix_error\": \"RecursionError\"}'"
    )
    env = {"PATH": f"{stub}:/usr/bin:/bin"}
    result = hooks.run("PostToolUse", {"tool_name": "Write", "tool_input": tool_input}, **env)
    assert "an internal error (RecursionError)" in json.loads(result.stdout)["systemMessage"]


def test_status_without_a_session_record(hooks: Hooks) -> None:
    assert "no record for this session yet" in hooks.status()


def test_session_start_says_once_that_scanning_is_on(hooks: Hooks) -> None:
    first = json.loads(hooks.run("SessionStart", {"source": "startup"}).stdout)
    assert "/kestrix:status" in first["systemMessage"] and "Stop gate off" in first["systemMessage"]
    second = json.loads(hooks.run("SessionStart", {"source": "compact"}).stdout)
    assert "systemMessage" not in second  # compaction re-adds the context for Claude, not the notice
    assert second["hookSpecificOutput"]["additionalContext"].startswith("Kestrix security hooks are active")


# ----- files changed by Bash commands

GIT = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
needs_git = pytest.mark.skipif(GIT is None, reason="needs git")


def _git(project: Path, *args: str) -> None:
    assert GIT is not None
    env = {"PATH": os.path.dirname(GIT), "HOME": str(project.parent), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        [GIT, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=project,
        env=env,
        check=True,
        capture_output=True,
    )


def _repo(hooks: Hooks, files: dict[str, str] | None = None) -> None:
    _git(hooks.project, "init", "-q")
    for name, text in (files or {"README.md": "# demo\n"}).items():
        (hooks.project / name).write_text(text)
    _git(hooks.project, "add", "-A")
    _git(hooks.project, "commit", "-q", "-m", "init")


def _write(hooks: Hooks, name: str, text: str) -> Callable[[], None]:
    return lambda: (hooks.project / name).write_text(text)


@needs_git
def test_bash_created_file_is_scanned_like_an_edit(hooks: Hooks) -> None:
    _repo(hooks)
    result = hooks.bash(_write(hooks, "tool.py", VULNERABLE), command="cat > tool.py <<EOF ... EOF")
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "PostToolUse"
    assert "this command introduced 1 security issue(s)" in output["additionalContext"]
    assert "tool.py:4 [HIGH] py.subprocess.shell_true (CWE-78)" in output["additionalContext"]
    assert '"kestrix"' not in result.stdout  # the scanner's counts never reach Claude Code
    assert "Scans completed: 1, covering 1 file(s)." in hooks.status()


@needs_git
def test_bash_failed_command_is_scanned_too(hooks: Hooks) -> None:
    _repo(hooks)
    result = hooks.bash(_write(hooks, "tool.py", VULNERABLE), failure=True)
    assert json.loads(result.stdout)["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"


@needs_git
def test_bash_clean_command_and_clean_file_are_silent(hooks: Hooks) -> None:
    _repo(hooks)
    assert hooks.bash(lambda: None).stdout == ""
    assert hooks.bash(_write(hooks, "ok.py", SAFE), call="toolu_b2").stdout == ""


@needs_git
def test_bash_modification_reports_only_new_findings_against_head(hooks: Hooks) -> None:
    _repo(hooks, {"app.py": VULNERABLE})
    same = hooks.bash(_write(hooks, "app.py", VULNERABLE + "\nVERSION = 2\n"))
    assert same.stdout == ""  # the old finding is in HEAD
    new = hooks.bash(_write(hooks, "app.py", VULNERABLE + MD5), call="toolu_b2")
    context = json.loads(new.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "py.crypto.weak_hash" in context and "py.subprocess.shell_true" not in context
    assert "1 existing issue(s)" in context


@needs_git
def test_bash_ignores_files_modified_before_the_command_gitignored_and_non_source(hooks: Hooks) -> None:
    _repo(hooks, {".gitignore": "build/\n", "README.md": "x\n"})
    old = hooks.project / "dirty.py"
    old.write_text(VULNERABLE)
    os.utime(old, (1_000_000, 1_000_000))  # untracked and vulnerable, but not touched by the command

    def effect() -> None:
        (hooks.project / "build").mkdir()
        (hooks.project / "build" / "gen.py").write_text(VULNERABLE)
        (hooks.project / "notes.txt").write_text(VULNERABLE)
        (hooks.project / "package-lock.json").write_text("{}")

    assert hooks.bash(effect).stdout == ""
    assert "Scans completed: 0" in hooks.status()


@needs_git
def test_bash_scans_at_most_twenty_files_and_says_so(hooks: Hooks) -> None:
    _repo(hooks)

    def effect() -> None:
        for number in range(23):
            (hooks.project / f"m{number:02}.py").write_text(VULNERABLE)

    result = json.loads(hooks.bash(effect).stdout)
    context = result["hookSpecificOutput"]["additionalContext"]
    assert "this command introduced" in context  # the 20 newest files were scanned
    assert "could NOT security-check" in context and "more than 20 files changed" in context
    assert "was not security-checked" in result["systemMessage"]
    status = hooks.status()
    assert "covering 20 file(s)" in status and "3 limit" in status


@needs_git
def test_bash_scan_failures_use_the_unavailable_state(tmp_path: Path) -> None:
    hooks = Hooks(tmp_path, kestrix_on_path=False)
    _repo(hooks)
    missing = json.loads(hooks.bash(_write(hooks, "a.py", VULNERABLE)).stdout)
    assert "neither kestrix-scan nor kestrix is on PATH" in missing["systemMessage"]
    assert "a.py" in missing["hookSpecificOutput"]["additionalContext"]
    _fake_scanner(tmp_path / "empty-bin", "exit 3")
    broken = json.loads(hooks.bash(_write(hooks, "b.py", VULNERABLE), call="toolu_b2").stdout)
    assert "failed with exit code 3" in broken["systemMessage"]
    assert "the files this command changed" in broken["systemMessage"]


def test_bash_outside_a_git_repository_is_skipped_with_one_notice(hooks: Hooks) -> None:
    first = hooks.bash(_write(hooks, "tool.py", VULNERABLE))
    assert "not inside a git repository" in json.loads(first.stdout)["systemMessage"]
    assert "hookSpecificOutput" not in json.loads(first.stdout)
    assert hooks.bash(_write(hooks, "tool2.py", VULNERABLE), call="toolu_b2").stdout == ""
    assert "1 no-git" in hooks.status() or "2 no-git" in hooks.status()


@needs_git
def test_bash_without_a_start_mark_says_nothing(hooks: Hooks) -> None:
    _repo(hooks)
    (hooks.project / "tool.py").write_text(VULNERABLE)
    tool = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_use_id": "toolu_none"}
    assert hooks.run("PostToolUse", tool, arg="bash-post").stdout == ""


@needs_git
def test_bash_changes_feed_the_stop_gate(hooks: Hooks) -> None:
    _repo(hooks, {"app.py": VULNERABLE})
    hooks.bash(_write(hooks, "app.py", VULNERABLE + "\nVERSION = 2\n"))
    assert hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout == ""  # the HEAD version is the session's starting point
    hooks.bash(_write(hooks, "new.py", VULNERABLE), call="toolu_b2")
    assert "new.py:4" in json.loads(hooks.stop(KESTRIX_BLOCK_ON_STOP="1").stdout)["reason"]


@needs_git
def test_git_runs_without_repository_configured_commands(hooks: Hooks, tmp_path: Path) -> None:
    """core.fsmonitor in a cloned repository's config would run a program on ``git status``; the hook turns it off."""
    _repo(hooks)
    marker = tmp_path / "ran"
    program = hooks.project.parent / "fsmon.sh"
    program.write_text(f"#!/bin/sh\ntouch {marker}\n")
    program.chmod(0o755)
    _git(hooks.project, "config", "core.fsmonitor", str(program))
    hooks.bash(_write(hooks, "tool.py", SAFE))
    assert not marker.exists()


def test_bash_source_like_names() -> None:
    spec = importlib.util.spec_from_file_location("kestrix_hook_names", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("a.py", "src/app.TSX", "x/.mcp.json", ".env", ".env.local", "deploy.sh", "settings.yaml"):
        assert module.source_like(name), name
    for name in ("notes.txt", "package-lock.json", "image.png", "Makefile", "uv.lock"):
        assert not module.source_like(name), name


@needs_git
def test_bash_scan_timeout_is_unavailable_and_once(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    hooks = Hooks(tmp_path)
    _repo(hooks)
    monkeypatch.setenv("PATH", f"{_fake_kestrix(tmp_path, '/bin/sleep 5')}:{os.path.dirname(GIT or '')}")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(hooks.data))
    monkeypatch.setattr(module, "SCAN_TIMEOUT_S", 0.5)
    replies = []
    for call in ("toolu_t1", "toolu_t2"):
        payload = {
            "session_id": "s",
            "cwd": str(hooks.project),
            "tool_name": "Bash",
            "tool_input": {"command": "x"},
            "tool_use_id": call,
        }
        module.bash_mark(payload)
        (hooks.project / f"{call}.py").write_text(VULNERABLE)
        module.bash_post({**payload, "hook_event_name": "PostToolUse"})
        replies.append(json.loads(capsys.readouterr().out))
    assert "timed out after" in replies[0]["systemMessage"]
    assert "systemMessage" not in replies[1]
    assert "toolu_t2.py" in replies[1]["hookSpecificOutput"]["additionalContext"]
