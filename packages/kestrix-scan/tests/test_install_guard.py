# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The install guard: command parsing, deny and warn decisions, opt-outs, failing open, and the plugin hook."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import osv_support as osv
import pytest
from cli_support import PLUGIN, run

from kestrix_scan import hook
from kestrix_scan.install_guard import Requested, parse_command

SCRIPT = PLUGIN / "hooks" / "kestrix_hook.py"
KESTRIX = shutil.which("kestrix-scan", path=str(Path(sys.executable).parent))


def py(name: str, version: str | None = None) -> Requested:
    return Requested("PyPI", name, version)


def js(name: str, version: str | None = None) -> Requested:
    return Requested("npm", name, version)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("pip install requests==2.19.0", [py("requests", "2.19.0")]),
        (
            "pip3 install -U 'Django[argon2]==4.2.0' 'flask>=2' 'numpy!=1.0'",
            [py("Django", "4.2.0"), py("flask"), py("numpy")],
        ),
        ("python3 -m pip install --index-url https://example.invalid/simple attrs===23.1.0", [py("attrs", "23.1.0")]),
        ("/usr/bin/python3.12 -m pip install x==1.*", [py("x")]),
        ("uv pip install --python 3.12 demo-pkg==2.0.0", [py("demo-pkg", "2.0.0")]),
        ("uv add 'evil-pkg>=1' --dev", [py("evil-pkg")]),
        ("cd web && npm i lodash@4.17.20 @scope/pkg@^1.0.0 -D", [js("lodash", "4.17.20"), js("@scope/pkg")]),
        ("npm install --save-dev --registry https://r.example.invalid left-pad", [js("left-pad")]),
        ("pnpm add react@18.2.0-rc.1", [js("react", "18.2.0-rc.1")]),
        ("yarn add @evil/stealer; echo done", [js("@evil/stealer")]),
        ("FOO=1 sudo pip install a==1 && pip install a==1 | tee log", [py("a", "1")]),
        ("pip install a==1\nnpm i b@2.0.0", [py("a", "1"), js("b", "2.0.0")]),
        # Skipped: requirement files, editable installs, URLs, paths, VCS and aliases.
        ("pip install -r requirements.txt -e . ./dist/pkg.whl git+https://example.invalid/r.git", []),
        ("pip install 'pkg @ https://example.invalid/pkg.zip'", []),
        ("npm install", []),
        ("npm i ./local file:../x github:user/repo alias@npm:real@1.0.0 https://example.invalid/x.tgz", []),
        ("npm ci", []),
        ("pip download requests==2.0", []),
        ("echo 'pip install requests==2.19.0'", []),
        ("pip install 'unbalanced", []),
        ("yarn install", []),
    ],
)
def test_parse_command(command: str, expected: list[Requested]) -> None:
    assert parse_command(command) == expected


@pytest.fixture
def index(isolated_osv_index: Path) -> Path:
    return osv.build(isolated_osv_index)


def _payload(command: str, cwd: Path | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
    if cwd is not None:
        body["cwd"] = str(cwd)
    return body


def _decide(command: str, cwd: Path | None = None) -> dict[str, Any] | None:
    out = hook.hook_response(json.dumps(_payload(command, cwd)))
    return json.loads(out)["hookSpecificOutput"] if out else None


def test_malicious_package_is_denied(index: Path) -> None:
    decision = _decide("npm i @evil/stealer && pip install evil_pkg")
    assert decision is not None and decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    reason = decision["permissionDecisionReason"]
    assert "@evil/stealer (npm) is reported as a malicious package: MAL-2026-200" in reason
    assert "evil_pkg (PyPI)" in reason and "MAL-2026-100" in reason
    assert "KESTRIX_INSTALL_GUARD=0" in reason


def test_compromised_version_is_denied_and_unpinned_name_is_warned(index: Path) -> None:
    pinned = _decide("pip install popular-lib==3.3.3")
    assert pinned is not None and pinned["permissionDecision"] == "deny"
    assert _decide("pip install popular-lib==3.3.4") is None
    unpinned = _decide("pip install popular-lib")
    assert unpinned is not None and "permissionDecision" not in unpinned
    assert (
        "Some versions of popular-lib (PyPI) are reported as malicious (MAL-2026-101; versions 3.3.3)"
        in unpinned["additionalContext"]
    )


def test_vulnerable_pinned_version_gets_a_non_blocking_warning(index: Path) -> None:
    decision = _decide("uv add demo_pkg==2.0.0 && npm i left-pad@1.3.0")
    assert decision is not None and "permissionDecision" not in decision
    context = decision["additionalContext"]
    assert "demo_pkg@2.0.0 (PyPI) has 2 known vulnerability(ies)" in context
    assert "install demo_pkg 2.0.1 or later instead; 1 of them have no fix yet" in context  # GHSA-dddd: last_affected
    assert (
        "left-pad@1.3.0 (npm) has 1 known vulnerability(ies): GHSA-npm1-npm1-npm1 (CVE-2026-0002); install left-pad 1.3.1 or later instead."
        in context
    )


def test_safe_and_unpinned_packages_pass_silently(index: Path) -> None:
    assert _decide("pip install demo-pkg==3.0 left-pad flask") is None
    assert _decide("ls -la") is None


def test_fails_open_without_an_index() -> None:
    assert _decide("npm i @evil/stealer") is None


def test_env_opt_out(index: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KESTRIX_INSTALL_GUARD", "0")
    assert _decide("npm i @evil/stealer") is None


def test_project_opt_out_and_ignored_advisories(index: Path, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[tool.kestrix]\nignore-advisories = {"MAL-2026-200" = "our own test package"}\n'
    )
    assert _decide("npm i @evil/stealer", project) is None
    assert _decide("pip install evil-pkg", project) is not None
    (project / "pyproject.toml").write_text("[tool.kestrix]\nclaude.install-guard = false\n")
    assert _decide("pip install evil-pkg", project) is None
    (project / "pyproject.toml").write_text(
        '[tool.kestrix]\nclaude.install-guard = "no"\n'
    )  # broken settings: guard stays on
    assert _decide("pip install evil-pkg", project) is not None


def test_cli_hook_mode_relays_the_decision_and_never_fails(index: Path) -> None:
    result = run("scan", "--hook", stdin=json.dumps(_payload("pip install evil-pkg")))
    assert result.exit_code == 0 and '"permissionDecision": "deny"' in result.stdout
    broken = run("scan", "--hook", stdin=json.dumps({**_payload("pip install x==1"), "tool_input": "not a dict"}))
    assert (broken.exit_code, broken.stdout) == (0, "")


# ----- the plugin's hook script, run as Claude Code runs it


def _hook(tmp_path: Path, payload: dict[str, Any], index_dir: Path, **env: str) -> subprocess.CompletedProcess[str]:
    bin_dir = Path(str(KESTRIX)).parent
    environment = {
        "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
        "HOME": str(tmp_path),
        "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
        "CLAUDE_PLUGIN_DATA": str(tmp_path / "plugin-data"),
        "KESTRIX_SCAN_DB": str(index_dir),
        **env,
    }
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    body = {"session_id": "s", "cwd": str(project), **payload}
    return subprocess.run(
        [sys.executable, str(SCRIPT), "install-guard"],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        cwd=project,
        env=environment,
        timeout=60,
        check=False,
    )


needs_scanner = pytest.mark.skipif(KESTRIX is None, reason="needs the kestrix-scan entry point next to the interpreter")


@needs_scanner
def test_plugin_hook_denies_a_malicious_install(tmp_path: Path, index: Path, isolated_osv_index: Path) -> None:
    result = _hook(tmp_path, _payload("npm install @evil/stealer"), isolated_osv_index)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse" and output["permissionDecision"] == "deny"


@needs_scanner
def test_plugin_hook_warns_and_fails_open(tmp_path: Path, index: Path, isolated_osv_index: Path) -> None:
    warned = _hook(tmp_path, _payload("pip install demo-pkg==2.0.0"), isolated_osv_index)
    assert "additionalContext" in json.loads(warned.stdout)["hookSpecificOutput"]
    for result in (
        _hook(tmp_path, _payload("npm install @evil/stealer"), tmp_path / "no-index"),
        _hook(tmp_path, _payload("npm install @evil/stealer"), isolated_osv_index, KESTRIX_INSTALL_GUARD="0"),
        _hook(tmp_path, _payload("npm install @evil/stealer"), isolated_osv_index, PATH="/usr/bin:/bin"),
        _hook(tmp_path, _payload("git status"), isolated_osv_index),
        _hook(tmp_path, {"tool_input": None}, isolated_osv_index),
    ):
        assert (result.returncode, result.stdout) == (0, ""), result.stderr
