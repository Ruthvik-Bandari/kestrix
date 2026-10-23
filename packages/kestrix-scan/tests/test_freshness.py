# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Index freshness (notes, hook line, SARIF, config) and the install guard for the added package managers."""

import json
from pathlib import Path
from typing import Any

import osv_support as osv
import pytest

from kestrix_scan import hook, scan
from kestrix_scan.cli import render
from kestrix_scan.config import load_file
from kestrix_scan.errors import Rejected
from kestrix_scan.install_guard import Requested, parse_command

OLD = "2020-01-01T00:00:00+00:00"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "p"
    root.mkdir()
    (root / "requirements.txt").write_text("demo-pkg==3.0\n")
    monkeypatch.chdir(root)
    return root


def _stale(report: Any) -> list[Any]:
    return [n for n in report.notes if n.id == "dep.db_stale"]


def test_stale_note_in_text_json_and_sarif(project: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index, downloaded_at=OLD)
    report = scan([project], root=project)
    [note] = _stale(report)
    assert "days old (limit 7)" in note.message and "db update" in note.message
    assert not report.findings and report.counts.critical == 0  # a note, never a finding
    assert "note: requirements.txt:1 dep.db_stale" in render(report, "text", color=False)
    assert json.loads(render(report, "json", color=False))["notes"][0]["id"] == "dep.db_stale"
    run_ = json.loads(render(report, "sarif", color=False))["runs"][0]
    [notification] = run_["invocations"][0]["toolExecutionNotifications"]
    assert notification["level"] == "note" and notification["descriptor"]["id"] == "dep.db_stale"
    assert run_["results"] == []


def test_missing_index_is_stated(project: Path) -> None:
    [note] = _stale(scan([project], root=project))
    assert "No vulnerability index" in note.message


def test_limit_from_config_and_env(project: Path, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    osv.build(isolated_osv_index, downloaded_at=OLD)
    config = project / ".kestrix.toml"
    config.write_text("db-max-age-days = 100000\n")
    assert not _stale(scan([project], root=project, config=load_file(config)))
    monkeypatch.setenv("KESTRIX_SCAN_MAX_AGE_DAYS", "1")  # the environment wins
    assert _stale(scan([project], root=project, config=load_file(config)))


def test_fresh_index_has_no_note(project: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index)
    assert not _stale(scan([project], root=project))


@pytest.mark.parametrize(
    "text", ["db-max-age-days = 0", 'db-max-age-days = "7"', "db-max-age-days = true", 'db-ecosystems = ["Bogus"]']
)
def test_bad_db_settings_are_rejected(project: Path, text: str) -> None:
    config = project / ".kestrix.toml"
    config.write_text(text + "\n")
    with pytest.raises(Rejected, match="db-"):
        load_file(config)


def test_db_settings_load(project: Path) -> None:
    config = project / ".kestrix.toml"
    config.write_text('db-max-age-days = 3\ndb-ecosystems = ["Go", "Pub"]\n')
    loaded = load_file(config)
    assert loaded.db_max_age_days == 3 and loaded.db_ecosystems == ("Go", "Pub") and not loaded.warnings


def _edit(path: Path) -> str | None:
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": str(path)},
        "tool_response": {"type": "create"},
        "cwd": str(path.parent),
    }
    return hook.hook_response(json.dumps(payload))


def test_hook_adds_one_line_when_a_dependency_file_is_edited_and_the_index_is_stale(
    project: Path, isolated_osv_index: Path
) -> None:
    out = json.loads(_edit(project / "requirements.txt") or "{}")
    context = out["hookSpecificOutput"]["additionalContext"]
    assert "no vulnerability index" in context and "\n" not in context
    osv.build(isolated_osv_index, downloaded_at=OLD)
    context = json.loads(_edit(project / "requirements.txt") or "{}")["hookSpecificOutput"]["additionalContext"]
    assert "days old" in context and "kestrix-scan db update" in context
    osv.build(isolated_osv_index)
    assert _edit(project / "requirements.txt") is None
    (project / "app.py").write_text("x = 1\n")
    osv.build(isolated_osv_index, downloaded_at=OLD)
    assert _edit(project / "app.py") is None  # other files get no freshness line


def _decide(command: str, cwd: Path | None = None) -> dict[str, Any] | None:
    body = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
    if cwd is not None:
        body["cwd"] = str(cwd)
    out = hook.hook_response(json.dumps(body))
    return json.loads(out)["hookSpecificOutput"] if out else None


def test_install_guard_says_when_the_result_may_be_stale(project: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index, downloaded_at=OLD)
    allowed = _decide("pip install flask==3.0.0")
    assert allowed is not None and "permissionDecision" not in allowed
    assert "days old" in allowed["additionalContext"]
    denied = _decide("pip install evil-pkg")
    assert (
        denied is not None
        and denied["permissionDecision"] == "deny"
        and "days old" in denied["permissionDecisionReason"]
    )
    osv.build(isolated_osv_index)
    assert _decide("pip install flask==3.0.0") is None


def test_install_guard_names_an_ecosystem_the_index_lacks(project: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index)
    decision = _decide("composer require acme/php-lib:2.3.1")
    assert decision is not None
    assert "no data for acme/php-lib (Packagist)" in decision["additionalContext"]
    assert "db update --ecosystem Packagist" in decision["additionalContext"]


def test_install_guard_checks_the_added_ecosystems(project: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index, ecosystems=osv.ALL)
    warned = _decide("composer require acme/php-lib:2.3.1 && go get github.com/acme/gomod@v1.3.0")
    assert warned is not None
    context = warned["additionalContext"]
    assert "acme/php-lib@2.3.1 (Packagist)" in context and "install acme/php-lib 2.3.5 or later" in context
    assert "github.com/acme/gomod@v1.3.0 (Go)" in context and "1.4.0" in context
    assert _decide("composer require acme/php-lib:2.3.5") is None


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            "composer require vendor/pkg:1.2.3 other/pkg:^2.0 --dev",
            [("Packagist", "vendor/pkg", "1.2.3"), ("Packagist", "other/pkg", None)],
        ),
        ("composer require vendor/pkg 1.2.3", [("Packagist", "vendor/pkg", "1.2.3")]),
        ("composer require -d app vendor/pkg", [("Packagist", "vendor/pkg", None)]),
        ("composer install", []),
        (
            "go get github.com/a/b@v1.2.3 golang.org/x/text@latest ./...",
            [("Go", "github.com/a/b", "v1.2.3"), ("Go", "golang.org/x/text", None)],
        ),
        ("go install example.com/cmd/tool@v0.1.0", [("Go", "example.com/cmd/tool", "v0.1.0")]),
        ("go build ./...", []),
        (
            "cargo add serde serde_json@=1.0.100 --features derive",
            [("crates.io", "serde", None), ("crates.io", "serde_json", "1.0.100")],
        ),
        ("cargo add mycrate --path ../mycrate", []),
        ("gem install rails -v 7.0.0", [("RubyGems", "rails", "7.0.0")]),
        (
            "gem install nokogiri:1.15.4 rack --version '>= 2'",
            [("RubyGems", "nokogiri", "1.15.4"), ("RubyGems", "rack", None)],
        ),
        ("gem install ./local.gem", []),
        ("dotnet add package Newtonsoft.Json --version 13.0.1", [("NuGet", "Newtonsoft.Json", "13.0.1")]),
        ("dotnet add app/App.csproj package Serilog", [("NuGet", "Serilog", None)]),
        ("dotnet add reference ../lib", []),
        ("bun add left-pad@1.3.0 && pnpm add react", [("npm", "left-pad", "1.3.0"), ("npm", "react", None)]),
    ],
)
def test_parse_added_install_commands(command: str, expected: list[tuple[str, str, str | None]]) -> None:
    assert parse_command(command) == [Requested(*item) for item in expected]


def _plugin_script() -> Any:
    import importlib.util

    from cli_support import PLUGIN

    spec = importlib.util.spec_from_file_location("kestrix_hook_under_test", PLUGIN / "hooks" / "kestrix_hook.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "command",
    [
        "composer require a/b",
        "go get x.com/y",
        "cargo add serde",
        "gem install rails",
        "dotnet add package X",
        "bun add x",
    ],
)
def test_plugin_forwards_the_added_install_commands(command: str) -> None:
    assert _plugin_script()._INSTALL_HINT.search(command)
    assert not _plugin_script()._INSTALL_HINT.search("ls -la && git status")


def test_plugin_status_reports_the_index(isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil
    import sys

    exe = shutil.which("kestrix-scan", path=str(Path(sys.executable).parent))
    if exe is None:
        pytest.skip("kestrix-scan is not installed")
    monkeypatch.setenv("PATH", str(Path(exe).parent) + ":" + str(Path(exe).parent))
    script = _plugin_script()
    assert "NONE" in script.index_status()
    osv.build(isolated_osv_index, downloaded_at=OLD)
    assert "STALE" in script.index_status() and "limit 7" in script.index_status()
    osv.build(isolated_osv_index)
    assert "STALE" not in script.index_status() and "Ecosystems: PyPI, npm" in script.index_status()
