# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""[tool.kestrix] and .kestrix.toml: discovery, every key, CLI precedence, warnings and errors."""

import json
from pathlib import Path

import pytest
from cli_support import run
from code_samples import fake

from kestrix_scan import Config, Rejected, hook, load_config, scan
from kestrix_scan.config import discover, find_config_file

SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
MD5 = "import hashlib\nh = hashlib.md5(b'')\n"  # medium


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()  # the discovery boundary
    (root / "app.py").write_text(SHELL)
    (root / "hashes.py").write_text(MD5)
    (root / "keys.env").write_text(f"GITHUB_TOKEN={fake('github_token')}\n")
    monkeypatch.chdir(root)
    return root


def pyproject(root: Path, body: str) -> None:
    (root / "pyproject.toml").write_text('[project]\nname = "demo"\n\n[tool.kestrix]\n' + body)


def rule_ids(result_stdout: str) -> set[str]:
    return {f["rule_id"] for f in json.loads(result_stdout)["findings"]}


def test_no_config_means_defaults(project: Path) -> None:
    assert discover(project) == Config()
    assert run("--format", "json").exit_code == 1


def test_fail_on_from_pyproject_and_the_flag_overrides_it(project: Path) -> None:
    pyproject(project, 'fail-on = "critical"\nrules.disable = ["secret."]\n')
    result = run("--format", "json")
    assert result.exit_code == 0 and json.loads(result.stdout)["fail_on"] == "critical"
    assert run("--fail-on", "high").exit_code == 1


def test_rules_enable_and_disable_take_ids_and_prefixes(project: Path) -> None:
    pyproject(project, 'rules.enable = ["secret.", "py.crypto"]\nrules.disable = ["py.crypto.weak_hash"]\n')
    assert rule_ids(run("--format", "json", "--fail-on", "none").stdout) == {"secret.github_token"}
    pyproject(project, '[tool.kestrix.rules]\ndisable = ["py.subprocess.shell_true"]\n')
    assert rule_ids(run("--format", "json", "--fail-on", "none").stdout) == {
        "py.crypto.weak_hash",
        "secret.github_token",
    }


def test_exclude_globs(project: Path) -> None:
    (project / "tests").mkdir()
    (project / "tests" / "fixture.py").write_text(SHELL)
    pyproject(project, 'exclude = ["tests/", "*.env", "hashes.py"]\n')
    report = json.loads(run("--format", "json", "--fail-on", "none").stdout)
    assert {f["path"] for f in report["findings"]} == {"app.py"}
    assert "tests/fixture.py" not in {s["path"] for s in report["files_skipped"]}
    named = json.loads(run("tests/fixture.py", "keys.env", "--format", "json", "--fail-on", "none").stdout)
    assert named["findings"] == [] and named["files_scanned"] == 0  # pre-commit passes file names


def test_exclude_double_star_and_anchored(project: Path) -> None:
    deep = project / "src" / "gen" / "deep"
    deep.mkdir(parents=True)
    (deep / "x.py").write_text(SHELL)
    config = Config(exclude=("src/**/deep",))
    assert config.excluded("src/gen/deep/x.py") and not config.excluded("app.py")
    assert not Config(exclude=("gen/",)).excluded("app.py") and Config(exclude=("gen/",)).excluded("src/gen/x.py")
    assert Config(exclude=("/src/gen",)).excluded("src/gen/x.py") and not Config(exclude=("/gen",)).excluded(
        "src/gen/x.py"
    )


def test_baseline_is_relative_to_the_config_file_and_the_flag_overrides_it(project: Path) -> None:
    assert run("--write-baseline", "conf/known.json").exit_code == 2  # the directory does not exist
    (project / "conf").mkdir()
    assert run("--write-baseline", "conf/known.json").exit_code == 0
    pyproject(project, 'baseline = "conf/known.json"\n')
    sub = project / "app_dir"
    sub.mkdir()
    result = run("--format", "json", "--fail-on", "low", ".")
    assert result.exit_code == 0 and json.loads(result.stdout)["baseline_filtered"] == 3
    (project / "empty.json").write_text("[]")
    assert run("--baseline", "empty.json").exit_code == 1
    assert run("--write-baseline", "again.json").exit_code == 0  # the configured baseline is not applied
    assert len(json.loads((project / "again.json").read_text())) == 3


def test_unknown_keys_warn_but_do_not_fail(project: Path) -> None:
    pyproject(project, 'fail-on = "critical"\nfail_on = "low"\nrules.enabled = ["py."]\n')
    result = run("--fail-on", "none")
    assert result.exit_code == 0
    assert "warning: " in result.stderr and "unknown key 'fail_on' ignored" in result.stderr
    assert "unknown key 'rules.enabled' ignored" in result.stderr
    assert load_config(project).warnings


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('rules.disable = ["py.subprocess.shell_tru"]', "did you mean 'py.subprocess.shell_true'?"),
        ('rules.enable = ["secrets."]', "did you mean 'secret.'?"),
        ('rules.disable = ["zzz"]', "run `kestrix-scan rules`"),
        ('fail-on = "severe"', "fail-on must be one of"),
        ("exclude = 3", "exclude must be a list"),
        ("rules = 3", "rules must be a table"),
        ("baseline = 1", "baseline must be a path"),
        ("[broken", "is not valid TOML"),
    ],
)
def test_bad_config_is_a_usage_error(project: Path, body: str, message: str) -> None:
    pyproject(project, body + "\n")
    result = run(".")
    assert result.exit_code == 2 and "Rejected (invalid_input):" in result.stderr
    assert message in result.stderr
    with pytest.raises(Rejected, match=r"kestrix|TOML|must|rule"):
        load_config(project)


def test_kestrix_toml_wins_and_the_nearest_file_is_used(project: Path) -> None:
    pyproject(project, 'fail-on = "low"\n')
    nested = project / "pkg"
    nested.mkdir()
    (nested / "mod.py").write_text(SHELL)
    assert find_config_file(nested) == project / "pyproject.toml"
    (nested / "pyproject.toml").write_text('[project]\nname = "inner"\n')  # no [tool.kestrix]: keep walking
    assert find_config_file(nested) == project / "pyproject.toml"
    (nested / ".kestrix.toml").write_text('fail-on = "critical"\n')
    assert find_config_file(nested) == nested / ".kestrix.toml"
    assert discover(nested).fail_on == "critical"
    assert run("pkg").exit_code == 1  # the scan root is the project: its pyproject applies
    (project / ".kestrix.toml").write_text('fail-on = "critical"\nrules.disable = ["secret."]\n')
    assert find_config_file(project) == project / ".kestrix.toml"


def test_discovery_stops_at_the_git_root(project: Path) -> None:
    (project.parent / ".kestrix.toml").write_text('fail-on = "none"\n')
    assert find_config_file(project) is None
    assert run().exit_code == 1


def test_explicit_config_and_no_config(project: Path, tmp_path: Path) -> None:
    pyproject(project, 'fail-on = "low"\n')
    other = tmp_path / "ci.toml"
    other.write_text('fail-on = "none"\n')
    assert run("--config", str(other)).exit_code == 0
    assert run("--config", str(tmp_path / "missing.toml")).exit_code == 2
    (project / "hashes.py").write_text("x = 1\n")
    (project / "keys.env").unlink()
    (project / "app.py").write_text(MD5)
    assert run().exit_code == 1  # fail-on low from pyproject
    assert run("--no-config").exit_code == 0  # default high


def test_api_config_and_explicit_arguments(project: Path) -> None:
    config = Config(fail_on="critical", disable=("secret.",))
    report = scan(["."], config=config)
    assert report.fail_on == "critical" and {f.rule_id for f in report.findings} == {
        "py.subprocess.shell_true",
        "py.crypto.weak_hash",
    }
    assert scan(["."], config=config, fail_on="low").fail_on == "low"


def test_hook_honours_disabled_rules(project: Path) -> None:
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(project / "app.py")}, "cwd": str(project)}
    assert "py.subprocess.shell_true" in (hook.hook_response(json.dumps(payload)) or "")
    pyproject(project, 'rules.disable = ["py.subprocess"]\nbaseline = "missing.json"\n')
    assert hook.hook_response(json.dumps(payload)) is None
