# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix-scan init``: appends, never rewrites user files, is idempotent and pins actions by SHA."""

import re
import sys
from pathlib import Path

import pytest
from cli_support import REPO, run

from kestrix_scan import init, load_config

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

USER_PYPROJECT = '[project]\nname = "demo"  # keep this comment\n\n[tool.ruff]\nline-length = 100\n'


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return root


def test_appends_tool_kestrix_without_rewriting_the_file(project: Path) -> None:
    (project / "pyproject.toml").write_text(USER_PYPROJECT)
    first = run("init")
    assert first.exit_code == 0 and "appended [tool.kestrix]" in first.stdout
    text = (project / "pyproject.toml").read_text()
    assert text.startswith(USER_PYPROJECT) and text.count("[tool.kestrix]") == 1
    assert tomllib.loads(text)["tool"]["kestrix"] == {"fail-on": "high", "exclude": []}
    assert load_config(project).fail_on == "high"
    second = run("init")
    assert second.exit_code == 0 and "already present; left unchanged" in second.stdout
    assert (project / "pyproject.toml").read_text() == text


def test_no_trailing_newline_is_handled(project: Path) -> None:
    (project / "pyproject.toml").write_text('[project]\nname = "demo"')
    assert run("init").exit_code == 0
    assert tomllib.loads((project / "pyproject.toml").read_text())["tool"]["kestrix"]["fail-on"] == "high"


def test_force_replaces_only_the_kestrix_table(project: Path) -> None:
    (project / "pyproject.toml").write_text(
        USER_PYPROJECT + '\n[tool.kestrix]\nfail-on = "low"\n\n[tool.other]\nx = 1\n'
    )
    result = run("init", "--force")
    assert result.exit_code == 0 and "replaced [tool.kestrix]" in result.stdout
    data = tomllib.loads((project / "pyproject.toml").read_text())
    assert data["tool"]["kestrix"]["fail-on"] == "high" and data["tool"]["other"] == {"x": 1}
    assert "# keep this comment" in (project / "pyproject.toml").read_text()


def test_force_refuses_a_table_written_another_way(project: Path) -> None:
    original = USER_PYPROJECT + '\n[tool.kestrix.rules]\ndisable = ["py."]\n'
    (project / "pyproject.toml").write_text(original)
    result = run("init", "--force")
    assert result.exit_code == 2 and "not a plain table section" in result.stderr
    assert (project / "pyproject.toml").read_text() == original


def test_broken_pyproject_is_refused(project: Path) -> None:
    (project / "pyproject.toml").write_text("[project\n")
    result = run("init")
    assert result.exit_code == 2 and "not valid TOML" in result.stderr
    assert (project / "pyproject.toml").read_text() == "[project\n"


def test_without_pyproject_writes_kestrix_toml(project: Path) -> None:
    assert "wrote the default settings" in run("init").stdout
    assert tomllib.loads((project / ".kestrix.toml").read_text()) == {"fail-on": "high", "exclude": []}
    assert not (project / "pyproject.toml").exists()
    assert "already present" in run("init").stdout


def test_pre_commit_written_once(project: Path) -> None:
    result = run("init", "--pre-commit")
    config = (project / ".pre-commit-config.yaml").read_text()
    assert "wrote the kestrix-scan hook" in result.stdout
    assert (
        config
        == f"repos:\n  - repo: https://github.com/Ruthvik-Bandari/kestrix\n    rev: v{init.__version__}\n    hooks:\n      - id: kestrix-scan\n"
    )
    assert "already configured" in run("init", "--pre-commit").stdout
    assert (project / ".pre-commit-config.yaml").read_text() == config


def test_pre_commit_with_other_content_is_printed_not_edited(project: Path) -> None:
    other = "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.14.0\n    hooks:\n      - id: ruff\n"
    (project / ".pre-commit-config.yaml").write_text(other)
    result = run("init", "--pre-commit")
    assert result.exit_code == 0 and "was not changed" in result.stdout and "id: kestrix-scan" in result.stdout
    assert (project / ".pre-commit-config.yaml").read_text() == other


def test_github_workflow(project: Path) -> None:
    result = run("init", "--ci", "github")
    path = project / ".github" / "workflows" / "kestrix.yml"
    text = path.read_text()
    assert "uploads kestrix.sarif" in result.stdout
    assert 'cron: "17 5 * * *"' in text and "push:\n" in text and "pull_request:\n" in text
    assert "${{ runner.os }}" in text and "timeout-minutes: 20" in text
    uses = re.findall(r"uses: (\S+)@(\S+) # (v[\d.]+)", text)
    assert [name for name, _, _ in uses] == [
        "actions/checkout",
        "actions/setup-python",
        "actions/cache",
        "github/codeql-action/upload-sarif",
    ]
    assert all(re.fullmatch(r"[0-9a-f]{40}", sha) for _, sha, _ in uses)
    assert "permissions:\n  contents: read\n" in text
    assert "      contents: read\n      security-events: write\n" in text
    assert f"pip install kestrix-scan=={init.__version__}" in text
    assert "kestrix-scan --format sarif --output kestrix.sarif || true" in text
    assert text.index("run: kestrix-scan db update") < text.index("run: kestrix-scan --format sarif")
    assert "already up to date" in run("init", "--ci", "github").stdout
    path.write_text("name: mine\n")
    assert "left unchanged" in run("init", "--ci", "github").stdout and path.read_text() == "name: mine\n"
    assert run("init", "--ci", "github", "--force").exit_code == 0 and path.read_text() == text


def test_workflow_pins_match_the_repository_ci(project: Path) -> None:
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    assert init.CHECKOUT.split(" # ")[0] in ci  # the same SHA the repository's own CI uses


def test_claude_plugin_install_is_idempotent(project: Path, tmp_path: Path) -> None:
    first = run("init", "--claude-plugin")
    dest = tmp_path / "home" / ".claude" / "kestrix-plugin"
    assert first.exit_code == 0 and "installed the Claude Code plugin" in first.stdout
    assert (dest / ".claude-plugin" / "plugin.json").is_file()
    assert "already installed" in run("init", "--claude-plugin").stdout
    assert "installed the Claude Code plugin" in run("init", "--claude-plugin", "--force").stdout


def test_every_step_together_prints_one_line_each(project: Path) -> None:
    (project / "pyproject.toml").write_text(USER_PYPROJECT)
    result = run("init", "--pre-commit", "--ci", "github", "--claude-plugin")
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert [line.split(":")[0] for line in lines[:3]] == [
        "pyproject.toml",
        ".pre-commit-config.yaml",
        ".github/workflows/kestrix.yml",
    ]
    assert len(lines) == 4 and "kestrix-plugin" in lines[3]


def test_missing_directory_is_refused(tmp_path: Path) -> None:
    result = run("init", "--dir", str(tmp_path / "nope"))
    assert result.exit_code == 2 and "is not a directory" in result.stderr
