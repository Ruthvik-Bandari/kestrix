# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The scanner and the Claude Code hooks open no sockets: they still work when every socket call raises."""

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cli_support import PLUGIN, run

from kestrix_scan import hook, scan

SCRIPT = PLUGIN / "hooks" / "kestrix_hook.py"
KESTRIX = shutil.which("kestrix-scan", path=str(Path(sys.executable).parent))
VULNERABLE = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"

# Loaded into every Python process of the end-to-end test: any socket use records a marker and raises.
SITECUSTOMIZE = """
import os, socket

def _refuse(*args, **kwargs):
    with open(os.environ["KESTRIX_SOCKET_MARKER"], "a") as handle:
        handle.write("socket used\\n")
    raise OSError("network disabled by the Kestrix no-network test")

class _NoSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        _refuse()

socket.socket = _NoSocket
socket.create_connection = _refuse
socket.getaddrinfo = _refuse
"""


class NoNetwork(OSError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        calls.append("socket")
        raise NoNetwork("network disabled for this test")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    return calls


def test_scan_and_hook_work_without_sockets(tmp_path: Path, no_network: list[str]) -> None:
    target = tmp_path / "app.py"
    target.write_text(VULNERABLE)
    assert [f.rule_id for f in scan([target], root=tmp_path).findings] == ["py.subprocess.shell_true"]
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "cwd": str(tmp_path)}
    assert "py.subprocess.shell_true" in (hook.hook_response(json.dumps(payload)) or "")
    stop = {"hook_event_name": "Stop", "cwd": str(tmp_path), "kestrix_files": [str(target)]}
    assert json.loads(hook.hook_response(json.dumps(stop)) or "{}")["kestrix_stop"]["new"]
    result = run("scan", "--hook", stdin=json.dumps(payload))
    assert "py.subprocess.shell_true" in result.stdout
    assert no_network == []


def test_plugin_snapshot_works_without_sockets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: list[str]
) -> None:
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # keep __pycache__ out of the packaged plugin
    spec = importlib.util.spec_from_file_location("kestrix_hook", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    target = tmp_path / "app.py"
    target.write_text(VULNERABLE)
    module.pre_tool_use({"session_id": "s", "cwd": str(tmp_path), "tool_input": {"file_path": str(target)}})
    assert list((tmp_path / "data" / "sessions" / "s" / "before-first").iterdir())
    assert no_network == []


@pytest.mark.skipif(KESTRIX is None, reason="needs the kestrix-scan entry point next to the interpreter")
def test_hook_processes_open_no_sockets(tmp_path: Path) -> None:
    """End to end: the hook script and the kestrix-scan process it starts, with sockets refused in every process."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(SITECUSTOMIZE)
    marker = tmp_path / "socket-marker"
    project = tmp_path / "project"
    project.mkdir()
    env = {
        "PATH": os.pathsep.join([str(Path(str(KESTRIX)).parent), "/usr/bin", "/bin"]),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(site),
        "CLAUDE_PLUGIN_DATA": str(tmp_path / "data"),
        "KESTRIX_SOCKET_MARKER": str(marker),
        "KESTRIX_BLOCK_ON_STOP": "1",
    }
    probe = subprocess.run(
        [sys.executable, "-c", "import socket; socket.socket()"], env=env, capture_output=True, check=False
    )
    assert probe.returncode != 0 and marker.read_text() == "socket used\n"  # the guard is active
    marker.unlink()

    def run(event: str, payload: dict[str, Any]) -> str:
        body = {"session_id": "s", "cwd": str(project), **payload}
        result = subprocess.run(
            [sys.executable, str(SCRIPT), event],
            input=json.dumps(body),
            capture_output=True,
            text=True,
            cwd=project,
            env=env,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    target = project / "app.py"
    tool = {"tool_name": "Write", "tool_input": {"file_path": str(target)}}
    assert run("pre-tool-use", tool) == ""
    target.write_text(VULNERABLE)
    assert "py.subprocess.shell_true" in run("post-tool-use", {**tool, "tool_response": {"type": "create"}})
    assert json.loads(run("stop", {"stop_hook_active": False}))["decision"] == "block"
    assert not marker.exists()
