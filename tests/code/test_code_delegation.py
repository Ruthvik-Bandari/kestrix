# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix code`` and ``kestrix integrations`` run kestrix-scan; ``kestrix.code`` re-exports it."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import kestrix_scan
from kestrix.cli import LAZY_GROUPS, app

runner = CliRunner()
SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "app.py").write_text(SHELL)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _scan_cli(*args: str) -> tuple[int, str]:
    completed = subprocess.run(
        [sys.executable, "-m", "kestrix_scan", *args], capture_output=True, text=True, check=False
    )
    return completed.returncode, completed.stdout


def _stable(text: str) -> str:
    return re.sub(r'"duration_ms": \d+', '"duration_ms": 0', text)


def test_code_group_help() -> None:
    result = runner.invoke(app, ["code", "--help"])
    assert result.exit_code == 0 and "Find security issues in source code" in result.stdout
    assert LAZY_GROUPS["code"][1] == "Find security issues in source code (exits non-zero on findings)."


@pytest.mark.parametrize(
    "args",
    [[], ["--format", "json"], ["--format", "sarif"], ["--fail-on", "critical"], ["--fail-on", "none"], ["nope"]],
)
def test_code_scan_matches_kestrix_scan(project: Path, args: list[str]) -> None:
    result = runner.invoke(app, ["code", "scan", *args])
    code, stdout = _scan_cli("scan", *args)
    assert result.exit_code == code
    assert _stable(result.stdout) == _stable(stdout)


def test_code_scan_usage_errors_and_help(project: Path) -> None:
    missing = runner.invoke(app, ["code", "scan", "nope"])
    assert missing.exit_code == 2 and "Rejected (invalid_input): path not found: nope" in missing.output
    assert runner.invoke(app, ["code", "scan", "--format", "xml"]).exit_code == 2
    help_result = runner.invoke(app, ["code", "scan", "--help"])
    assert help_result.exit_code == 0 and "usage: kestrix code scan" in help_result.stdout


def test_code_scan_hook_mode(project: Path) -> None:
    payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(project / "app.py")}})
    result = runner.invoke(app, ["code", "scan", "--hook"], input=payload)
    assert result.exit_code == 0 and "py.subprocess.shell_true" in result.stdout
    bad = runner.invoke(app, ["code", "scan", "--hook"], input="not json")
    assert bad.exit_code == 0 and bad.stdout == "" and "kestrix code scan --hook: skipped" in bad.output


def test_integrations_delegate_to_the_installers(tmp_path: Path) -> None:
    dest = tmp_path / "plugin"
    result = runner.invoke(app, ["integrations", "install-claude-plugin", "--dest", str(dest)])
    assert result.exit_code == 0 and f"Installed the kestrix plugin to {dest}" in result.stdout
    assert (dest / ".claude-plugin" / "plugin.json").is_file()
    again = runner.invoke(app, ["integrations", "install-claude-plugin", "--dest", str(dest)])
    assert again.exit_code == 2 and "pass --force" in again.stderr
    skill = runner.invoke(app, ["integrations", "install-claude-skill", "--dest", str(tmp_path / "skill")])
    assert skill.exit_code == 0 and (tmp_path / "skill" / "SKILL.md").is_file()
    assert (
        runner.invoke(app, ["integrations", "uninstall-claude-skill", "--dest", str(tmp_path / "skill")]).exit_code == 0
    )
    for name in ("package-claude-skill", "package-claude-plugin"):
        out = tmp_path / f"{name}.zip"
        assert runner.invoke(app, ["integrations", name, "--out", str(out)]).exit_code == 0 and out.is_file()


def test_kestrix_code_reexports_kestrix_scan() -> None:
    from kestrix.code.analyze import write_baseline
    from kestrix.code.models import ScanReport
    from kestrix.code.rules import RULES

    from kestrix import code

    assert code.scan is kestrix_scan.scan and code.exit_code is kestrix_scan.exit_code
    assert code.Finding is kestrix_scan.Finding and ScanReport is kestrix_scan.ScanReport
    assert RULES is kestrix_scan.registry.RULES and write_baseline is kestrix_scan.analyze.write_baseline
    assert set(code.__all__) == set(kestrix_scan.__all__)


@pytest.mark.parametrize("argv", [["--help"], ["code", "scan", "--help"], ["version"]])
def test_light_commands_do_not_import_the_heavy_modules(argv: list[str]) -> None:
    code = (
        "import sys\n"
        f"sys.argv = ['kestrix', *{argv!r}]\n"
        "from kestrix.cli import app\n"
        "try:\n    app()\nexcept SystemExit:\n    pass\n"
        "heavy = {'fastapi', 'starlette', 'uvicorn', 'sigma', 'pydantic', 'httpx', 'yaml', 'anthropic'}\n"
        "print('HEAVY', sorted({m.split('.')[0] for m in sys.modules} & heavy))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert "HEAVY []" in out
