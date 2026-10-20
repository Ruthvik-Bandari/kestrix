# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run ``kestrix_scan.cli.main`` in-process with captured stdout and stderr and an optional stdin."""

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from kestrix_scan.cli import main

REPO = Path(__file__).resolve().parents[3]
PACKAGE = Path(__file__).resolve().parents[1]
PLUGIN = PACKAGE / "src" / "kestrix_scan" / "claude_plugin" / "kestrix"


@dataclass
class Result:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def run(*args: str, stdin: str | None = None, prog: str = "kestrix-scan") -> Result:
    out, err = io.StringIO(), io.StringIO()
    stream = io.TextIOWrapper(io.BytesIO((stdin or "").encode()), encoding="utf-8")
    with redirect_stdout(out), redirect_stderr(err), mock.patch.object(sys, "stdin", stream):
        code = main(list(args), prog=prog)
    return Result(code, out.getvalue(), err.getvalue())
