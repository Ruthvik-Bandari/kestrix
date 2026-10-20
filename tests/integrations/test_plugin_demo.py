# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The plugin demo's expected output is current, and its fake token is never committed."""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "docs" / "demo"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_expected_output_matches_the_current_scanner_and_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    generator = _load("build_demo_expected", REPO / "scripts" / "build_demo_expected.py")
    monkeypatch.setattr("sys.argv", ["build", "--check"])
    assert generator.main() == 0, "run: uv run python scripts/build_demo_expected.py"
    files = generator.render()
    assert "py.os.system" in files["post-tool-use.json"]
    assert '"decision": "block"' in files["stop.json"]
    assert "(Stop gate on)" in files["session-start.json"]
    for rule in ("py.sql.string_built", "py.subprocess.shell_true", "py.crypto.weak_hash", "secret.github_token"):
        assert rule in files["scan.txt"]


def test_setup_plants_a_fake_token_only_at_run_time(tmp_path: Path) -> None:
    setup = _load("setup_demo", DEMO / "setup_demo.py")
    dest = setup.setup(tmp_path / "demo")
    token = setup.fake_github_token()
    assert token in (dest / "settings_local.py").read_text()
    shape = re.compile(rb"gh" + rb"p_[A-Za-z0-9]{36}")
    committed = [p for p in DEMO.rglob("*") if p.is_file() and shape.search(p.read_bytes())]
    assert committed == []
    with pytest.raises(SystemExit, match="not empty"):
        setup.setup(dest)
