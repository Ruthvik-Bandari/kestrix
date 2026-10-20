# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The plugin's hooks, and the kestrix-scan processes they start, open no network connection.

Run from the repository root with the kestrix-scan you use on PATH:

    python3 -m unittest discover -s tests -v

Every hook event runs as Claude Code runs it: ``python3 hooks/kestrix_hook.py <event>`` with the hook JSON
on stdin. A ``sitecustomize`` module on ``PYTHONPATH`` replaces ``socket.socket``,
``socket.create_connection`` and ``socket.getaddrinfo`` in the hook process and in every Python process it
starts, including ``kestrix-scan``. Any attempt writes a marker file and raises. The test then checks that the
hooks still did their work (the findings came back) and that the marker file was never written.
Standard library only; Python 3.9 or later.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "kestrix_hook.py"
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
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


@unittest.skipIf(shutil.which("kestrix-scan") is None, "kestrix-scan is not on PATH")
class HooksOpenNoSockets(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = self.tmp / "project"
        self.project.mkdir()
        guard = self.tmp / "guard"
        guard.mkdir()
        (guard / "sitecustomize.py").write_text(SITECUSTOMIZE)
        self.marker = self.tmp / "socket-marker"
        self.env = {
            **os.environ,
            "PYTHONPATH": str(guard),
            "KESTRIX_SOCKET_MARKER": str(self.marker),
            "CLAUDE_PLUGIN_DATA": str(self.tmp / "data"),
            "CLAUDE_PROJECT_DIR": str(self.project),
            "KESTRIX_BLOCK_ON_STOP": "1",
        }
        self.base = {"session_id": "no-network-test", "cwd": str(self.project)}

    def hook(self, event: str, payload: dict) -> str:
        result = subprocess.run(
            [sys.executable, str(HOOK), event],
            input=json.dumps({**self.base, **payload}).encode(),
            capture_output=True,
            cwd=str(self.project),
            env=self.env,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout.decode()

    def test_every_hook_works_with_sockets_refused(self) -> None:
        target = self.project / "app.py"
        write = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": str(target)}}

        self.assertIn(
            "Kestrix security hooks are active", self.hook("session-start", {"hook_event_name": "SessionStart"})
        )
        self.assertEqual(self.hook("pre-tool-use", write), "")
        target.write_text(VULNERABLE)
        post = self.hook("post-tool-use", {**write, "hook_event_name": "PostToolUse"})
        self.assertIn("py.subprocess.shell_true", post)
        stop = json.loads(self.hook("stop", {"hook_event_name": "Stop", "stop_hook_active": False}))
        self.assertEqual(stop["decision"], "block")
        self.assertIn("py.subprocess.shell_true", stop["reason"])
        # The install guard reads only the local OSV index; with or without one it opens no socket.
        bash = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "npm install left-pad"}}
        self.hook("install-guard", bash)

        self.assertFalse(self.marker.exists(), "a hook or kestrix-scan tried to open a socket")

    def test_the_guard_itself_works(self) -> None:
        """The sitecustomize really refuses sockets in a child process, so the test above can fail."""
        probe = "import socket\ntry:\n    socket.create_connection(('example.com', 443))\nexcept OSError:\n    pass\n"
        subprocess.run([sys.executable, "-c", probe], env=self.env, check=True, timeout=30)
        self.assertTrue(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
