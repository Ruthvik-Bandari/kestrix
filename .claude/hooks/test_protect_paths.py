#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Tests for protect_paths.py. Runs the hook as a subprocess. Stdlib unittest only.

Usage: python3 .claude/hooks/test_protect_paths.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protect_paths.py")


class ProtectPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self._tmp.name)
        self.project = os.path.join(base, "project")
        self.outside = os.path.join(base, "outside")
        for d in ("analysis/src", "data/raw", "data/locked", "outside_target"):
            os.makedirs(os.path.join(self.project, d), exist_ok=True)
        os.makedirs(self.outside, exist_ok=True)
        # Innocent-looking symlink that points into data/raw.
        os.symlink(os.path.join(self.project, "data", "raw"), os.path.join(self.project, "fixtures_link"))
        # Symlink inside the project that points outside it.
        os.symlink(self.outside, os.path.join(self.project, "escape_link"))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_hook(self, stdin: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, CLAUDE_PROJECT_DIR=self.project)
        return subprocess.run(
            [sys.executable, HOOK], input=stdin, capture_output=True, text=True, env=env, cwd=self.project, timeout=30
        )

    def payload(self, path: str, key: str = "file_path", tool: str = "Write") -> str:
        return json.dumps({"tool_name": tool, "cwd": self.project, "tool_input": {key: path}})

    def assertAllowed(self, path: str, **kw) -> None:
        r = self.run_hook(self.payload(path, **kw))
        self.assertEqual(r.returncode, 0, f"expected allow for {path}: {r.stderr}")

    def assertDenied(self, path: str, **kw) -> None:
        r = self.run_hook(self.payload(path, **kw))
        self.assertEqual(r.returncode, 2, f"expected deny for {path}")
        self.assertIn("blocked", r.stderr)

    def test_normal_file_allowed(self):
        self.assertAllowed(os.path.join(self.project, "analysis/src/parser.py"))
        self.assertAllowed("analysis/src/parser.py")

    def test_env_denied(self):
        self.assertDenied(os.path.join(self.project, ".env"))
        self.assertDenied("backend/.env.local")

    def test_env_example_allowed(self):
        self.assertAllowed(os.path.join(self.project, ".env.example"))

    def test_key_material_denied(self):
        self.assertDenied("certs/server.pem")
        self.assertDenied("certs/server.key")

    def test_traversal_into_locked_denied(self):
        self.assertDenied(os.path.join(self.project, "analysis/../data/locked/x"))
        self.assertDenied("analysis/../data/locked/x")

    def test_raw_and_secrets_denied(self):
        self.assertDenied("data/raw/events.jsonl")
        self.assertDenied("config/secrets/token.txt")

    def test_symlink_into_raw_denied(self):
        self.assertDenied(os.path.join(self.project, "fixtures_link", "events.jsonl"))

    def test_symlink_escaping_project_denied(self):
        self.assertDenied(os.path.join(self.project, "escape_link", "x.txt"))

    def test_absolute_outside_denied(self):
        self.assertDenied(os.path.join(self.outside, "notes.txt"))
        self.assertDenied("../outside/notes.txt")

    def test_notebook_path_checked(self):
        self.assertDenied("data/locked/eval.ipynb", key="notebook_path", tool="NotebookEdit")
        self.assertAllowed("analysis/notebooks/eda.ipynb", key="notebook_path", tool="NotebookEdit")

    def test_malformed_json_denied(self):
        r = self.run_hook("{not json")
        self.assertEqual(r.returncode, 2)

    def test_missing_path_denied(self):
        r = self.run_hook(json.dumps({"tool_input": {}}))
        self.assertEqual(r.returncode, 2)
        r = self.run_hook(json.dumps(["not", "an", "object"]))
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
