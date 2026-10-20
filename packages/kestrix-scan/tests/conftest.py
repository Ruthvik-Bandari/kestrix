# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

GIT = shutil.which("git")


@pytest.fixture
def git() -> Callable[..., str]:
    if GIT is None:
        pytest.skip("git is not installed")
    git_path = GIT

    def run(cwd: Path, *args: str) -> str:
        env_args = [
            "-c",
            "user.name=Kestrix Test",
            "-c",
            "user.email=test@kestrix.example",
            "-c",
            "commit.gpgsign=false",
        ]
        out = subprocess.run([git_path, *env_args, *args], cwd=cwd, capture_output=True, text=True, check=True)
        return out.stdout

    return run


@pytest.fixture
def repo(tmp_path: Path, git: Callable[..., str]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


pytest_plugins = ["pytester"]
