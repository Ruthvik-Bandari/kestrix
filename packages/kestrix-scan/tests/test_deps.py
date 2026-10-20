# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dependency findings in scans: vulnerable and malicious packages, suppression, the stale note and output formats."""

import json
from pathlib import Path

import osv_support as osv
import pytest
from cli_support import run

from kestrix_scan import deps, scan
from kestrix_scan.cli import render
from kestrix_scan.config import Config, load_file
from kestrix_scan.errors import Rejected
from kestrix_scan.sarif import to_sarif
from kestrix_scan.walk import MAX_FILE_BYTES

PACKAGE_LOCK = {
    "name": "web",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "web"},
        "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/@evil/stealer": {"version": "0.0.1"},
        "node_modules/safe": {"version": "1.0.0"},
    },
}


@pytest.fixture
def project(tmp_path: Path, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    osv.build(isolated_osv_index)
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("demo-pkg==2.0.0\nevil_pkg==1.0\npopular-lib==3.3.4\nflask>=2\n")
    (root / "package-lock.json").write_text(json.dumps(PACKAGE_LOCK, indent=2))
    monkeypatch.chdir(root)
    return root


def _by_rule(root: Path, **kwargs: object) -> dict[tuple[str, str], object]:
    report = scan([root], root=root, **kwargs)  # type: ignore[arg-type]
    return {(f.path, f.rule_id): f for f in report.findings}


def test_vulnerable_and_malicious_dependencies(project: Path) -> None:
    report = scan([project], root=project)
    found = {(f.path, f.line, f.rule_id): f for f in report.findings}
    assert set(found) == {
        ("requirements.txt", 1, "dep.vulnerable"),
        ("requirements.txt", 2, "dep.malicious"),
        ("package-lock.json", 8, "dep.vulnerable"),
        ("package-lock.json", 11, "dep.malicious"),
    }
    demo = found[("requirements.txt", 1, "dep.vulnerable")]
    assert demo.severity == "critical" and demo.cwe == "CWE-94"
    # GHSA-aaaa and PYSEC-2026-1 are one vulnerability (aliases); GHSA-dddd is the second.
    assert "demo-pkg@2.0.0 (PyPI) has 2 known vulnerability(ies)" in demo.message
    assert "GHSA-aaaa-bbbb-cccc (CVE-2026-0001)" in demo.message and "GHSA-dddd-eeee-ffff" in demo.message
    assert "fixed in 2.0.1" in demo.message
    assert demo.fix.startswith("Upgrade demo-pkg to 2.0.1 or later; some vulnerabilities have no fix yet")
    left_pad = found[("package-lock.json", 8, "dep.vulnerable")]
    assert left_pad.severity == "medium" and left_pad.cwe == "CWE-1395"
    assert left_pad.fix == "Upgrade left-pad to 1.3.1 or later and update the lockfile."
    evil = found[("package-lock.json", 11, "dep.malicious")]
    assert evil.severity == "critical" and evil.cwe == "CWE-506" and "rotate" in evil.fix
    assert "@evil/stealer@0.0.1 (npm) is reported as a malicious package: MAL-2026-200" in evil.message
    assert report.counts.critical == 3 and report.counts.medium == 1
    # popular-lib 3.3.4 is not the compromised 3.3.3; flask is unpinned and only noted.
    assert [n.id for n in report.notes] == ["dep.not_checked"]
    assert "flask>=2" in report.notes[0].message


def test_fixed_versions_are_not_reported(project: Path) -> None:
    (project / "requirements.txt").write_text("demo-pkg==2.1.1\npopular-lib==3.3.3\n")
    found = _by_rule(project)
    assert ("requirements.txt", "dep.vulnerable") not in found
    assert ("requirements.txt", "dep.malicious") in found  # the listed compromised version


def test_last_affected_boundary(project: Path) -> None:
    (project / "requirements.txt").write_text("demo-pkg==2.1.0\n")
    finding = _by_rule(project)[("requirements.txt", "dep.vulnerable")]
    assert "GHSA-dddd-eeee-ffff" in finding.message and "no fixed version" in finding.message  # type: ignore[attr-defined]
    assert finding.severity == "medium"  # type: ignore[attr-defined]


def test_inline_suppression_by_rule_or_advisory_id(project: Path) -> None:
    (project / "requirements.txt").write_text(
        "demo-pkg==2.1.0  # kestrix: ignore[GHSA-dddd-eeee-ffff] we never call the leaking API\n"
        "\n"
        "# kestrix: ignore[dep.malicious] vetted internal mirror of the same name\n"
        "evil-pkg==1.0\n"
        "demo-pkg==2.0.0  # kestrix: ignore[CVE-2026-0001] only the alias is named\n"
    )
    report = scan([project], root=project)
    req = [f for f in report.findings if f.path == "requirements.txt"]
    assert [(f.line, f.rule_id) for f in req] == [(5, "dep.vulnerable")]
    assert "GHSA-aaaa" not in req[0].message and "GHSA-dddd-eeee-ffff" in req[0].message
    assert report.suppressed == 2


def test_ignore_advisories_from_config(project: Path) -> None:
    (project / "pyproject.toml").write_text(
        '[tool.kestrix]\nignore-advisories = {"GHSA-npm1-npm1-npm1" = "left-pad is only used in a build script", '
        '"MAL-2026-200" = "test fixture"}\n'
    )
    settings = load_file(project / "pyproject.toml")
    assert settings.ignore_advisories == (
        ("GHSA-npm1-npm1-npm1", "left-pad is only used in a build script"),
        ("MAL-2026-200", "test fixture"),
    )
    report = scan([project], root=project, config=settings)
    assert not [f for f in report.findings if f.path == "package-lock.json"]
    assert report.suppressed == 2


def test_ignore_advisories_needs_a_reason(tmp_path: Path) -> None:
    config = tmp_path / ".kestrix.toml"
    config.write_text('ignore-advisories = {"GHSA-x" = ""}\n')
    with pytest.raises(Rejected, match="needs a reason"):
        load_file(config)
    config.write_text('ignore-advisories = ["GHSA-x"]\n')
    with pytest.raises(Rejected, match="must be a table"):
        load_file(config)


def test_rules_disable_and_baseline_apply(project: Path, tmp_path: Path) -> None:
    disabled = scan([project], root=project, config=Config(disable=("dep.vulnerable",)))
    assert {f.rule_id for f in disabled.findings} == {"dep.malicious"}
    first = scan([project], root=project)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([f.fingerprint for f in first.findings]))
    again = scan([project], root=project, baseline=baseline)
    assert again.findings == [] and again.baseline_filtered == 4


def test_new_advisory_changes_the_fingerprint(project: Path, isolated_osv_index: Path) -> None:
    before = {f.fingerprint for f in scan([project], root=project).findings}
    extra = osv.advisory("GHSA-new0-new0-new0", "npm", "left-pad", events=[{"introduced": "0"}, {"fixed": "2.0.0"}])
    osv.build(isolated_osv_index, ecosystems={"PyPI": osv.PYPI, "npm": [*osv.NPM, extra]})
    deps._INDEX.db = None  # reopen the rebuilt index
    after = {f.fingerprint for f in scan([project], root=project).findings}
    assert len(before - after) == 1  # a baselined finding resurfaces when a new advisory affects it


def test_sarif_points_at_the_lockfile_line(project: Path) -> None:
    sarif = to_sarif(scan([project], root=project))
    run_ = sarif["runs"][0]
    rule_ids = [rule["id"] for rule in run_["tool"]["driver"]["rules"]]
    results = {
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]): r for r in run_["results"]
    }
    result = results[("dep.malicious", "package-lock.json")]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 11
    assert result["level"] == "error" and result["properties"]["cwe"] == "CWE-506"
    assert rule_ids[result["ruleIndex"]] == "dep.malicious"
    snippet = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    assert snippet == "@evil/stealer@0.0.1 MAL-2026-200"


def test_text_and_json_output(project: Path) -> None:
    report = scan([project], root=project)
    text = render(report, "text", color=False)
    assert "package-lock.json\n  8:1  MEDIUM  dep.vulnerable  CWE-1395" in text
    assert "fix: Upgrade left-pad to 1.3.1 or later" in text
    data = json.loads(render(report, "json", color=False))
    assert {f["rule_id"] for f in data["findings"]} == {"dep.vulnerable", "dep.malicious"}
    result = run("--format", "json", ".")
    assert result.exit_code == 1 and json.loads(result.stdout)["counts"]["critical"] == 3


def test_stale_note_when_missing_once_per_scan(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("demo-pkg==2.0.0\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "requirements.txt").write_text("demo-pkg==2.0.0\n")
    report = scan([tmp_path], root=tmp_path)
    assert report.findings == []
    stale = [n for n in report.notes if n.id == "dep.db_stale"]
    assert (
        len(stale) == 1
        and "kestrix-scan db update" in stale[0].message
        and "No vulnerability index" in stale[0].message
    )
    from kestrix_scan.analyze import exit_code

    assert exit_code(report) == 0


def test_stale_note_for_an_old_index_and_none_for_a_fresh_one(project: Path, isolated_osv_index: Path) -> None:
    assert not [n for n in scan([project], root=project).notes if n.id == "dep.db_stale"]
    osv.build(isolated_osv_index, downloaded_at="2026-01-01T00:00:00+00:00")
    deps._INDEX.db = None
    stale = [n for n in scan([project], root=project).notes if n.id == "dep.db_stale"]
    assert len(stale) == 1 and "days old" in stale[0].message


def test_no_stale_note_without_dependency_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n")
    assert scan([tmp_path], root=tmp_path).notes == []


def test_large_lockfiles_are_checked_without_secret_rules(project: Path) -> None:
    lock = dict(PACKAGE_LOCK)
    lock["padding"] = "x" * (MAX_FILE_BYTES + 10)
    (project / "package-lock.json").write_text(json.dumps(lock, indent=2))
    report = scan([project], root=project)
    assert ("package-lock.json", "dep.malicious") in {(f.path, f.rule_id) for f in report.findings}
    assert not report.files_skipped


def test_unsupported_lockfile_is_noted(project: Path) -> None:
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    notes = {n.id: n for n in scan([project], root=project).notes}
    assert "lockfileVersion 1" in notes["dep.unsupported"].message


def test_hook_reports_only_dependencies_an_edit_added(project: Path) -> None:
    from kestrix_scan import hook

    target = project / "requirements.txt"
    before = target.read_text()
    target.write_text(before + "left-pad==1.0.0\n")  # not a PyPI advisory: nothing new
    payload = {
        "tool_name": "Edit",
        "cwd": str(project),
        "tool_input": {
            "file_path": str(target),
            "old_string": "flask>=2\n",
            "new_string": "flask>=2\nleft-pad==1.0.0\n",
        },
    }
    assert hook.hook_response(json.dumps(payload)) is None
    target.write_text(before + "Demo_Pkg==1.9\n")
    payload["tool_input"] = {
        "file_path": str(target),
        "old_string": "flask>=2\n",
        "new_string": "flask>=2\nDemo_Pkg==1.9\n",
    }
    reply = json.loads(hook.hook_response(json.dumps(payload)) or "{}")
    context = reply["hookSpecificOutput"]["additionalContext"]
    assert "Demo_Pkg@1.9" in context and "this edit introduced 1 security issue" in context
