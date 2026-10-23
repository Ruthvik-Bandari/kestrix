# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The generated standalone plugin repository is reproducible, matches the packaged plugin and passes the checklist."""

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest

from kestrix_scan import plugin, scan
from kestrix_scan.about import __version__
from kestrix_scan.registry import rules as registry_rules

REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "packages/kestrix-scan/src/kestrix_scan/claude_plugin/kestrix"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_plugin_repo", REPO / "scripts" / "build_plugin_repo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = _load()
TREE = build.render()
FILES = {str(path): data for path, data in TREE}


def _text(name: str) -> str:
    return FILES[name].decode("utf-8")


def test_two_builds_are_byte_identical(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    build.write(first, build.render())
    build.write(second, build.render())
    assert build.read_tree(first) == build.read_tree(second) == TREE
    assert build.main(["--out", str(first), "--check"]) == 0


def test_the_plugin_files_match_the_packaged_plugin_byte_for_byte() -> None:
    packaged = {str(path): data for path, data in plugin.plugin_files() if path != plugin.MARKETPLACE}
    assert {name: FILES[name] for name in packaged} == packaged
    on_disk = {p.relative_to(PLUGIN_SRC).as_posix(): p.read_bytes() for p in PLUGIN_SRC.rglob("*") if p.is_file()}
    on_disk = {k: v for k, v in on_disk.items() if "__pycache__" not in k}
    assert on_disk == packaged
    extras = set(FILES) - set(packaged)
    assert all(not name.startswith(("hooks/", "skills/")) for name in extras)


def test_the_repository_files_are_the_documented_set() -> None:
    top = {name.split("/")[0] for name in FILES}
    assert top == {
        ".claude-plugin",
        ".gitignore",
        "CHANGELOG.md",
        "LICENSE",
        "NOTICE",
        "PRIVACY.md",
        "README.md",
        "SECURITY.md",
        "benchmarks",
        "evals",
        "hooks",
        "scripts",
        "skills",
        "tests",
    }
    assert FILES["LICENSE"] == (REPO / "packages/kestrix-scan/LICENSE").read_bytes()
    assert _text("LICENSE").lstrip().startswith("Apache License")
    assert "evals/results/" in _text(".gitignore").splitlines()


def test_check_mode_reports_drift(tmp_path: Path) -> None:
    out = tmp_path / "repo"
    assert build.main(["--out", str(out), "--check"]) == 1
    build.main(["--out", str(out)])
    (out / "README.md").write_text("changed")
    assert build.main(["--out", str(out), "--check"]) == 1


def test_marketplace_self_hosts_the_root_plugin() -> None:
    market = json.loads(FILES[".claude-plugin/marketplace.json"])
    manifest = json.loads(FILES[".claude-plugin/plugin.json"])
    (entry,) = market["plugins"]
    assert market["name"] == "kestrix" and market["owner"]["name"] == "Ruthvik Bandari"
    assert entry["name"] == manifest["name"] == plugin.PLUGIN_NAME
    assert entry["source"] == "./"
    assert entry["version"] == manifest["version"] == __version__
    assert entry["homepage"] == manifest["homepage"] == manifest["repository"] == build.REPO_URL
    assert entry["license"] == manifest["license"] == "Apache-2.0"
    assert f"## {__version__}" in _text("CHANGELOG.md")


def test_the_checklist_audit_passes_and_catches_each_problem() -> None:
    assert build.audit(TREE) == []
    files = dict(TREE)
    hook = PurePosixPath("hooks/kestrix_hook.py")
    broken = {
        "size": {**files, PurePosixPath("big.md"): b"x" * build.MAX_TEXT_BYTES},
        "binary": {**files, PurePosixPath("logo.ico"): b"\x00\xff\xfe"},
        "system file": {**files, PurePosixPath("skills/.DS_Store"): b""},
        "launcher": {**files, hook: files[hook] + b"\n# then: npx some-tool@latest\n"},
        "install": {**files, hook: files[hook] + b"\n# pip install requests\n"},
        "registry": {**files, PurePosixPath(".npmrc"): b"registry=https://example.invalid\n"},
        "lockfile": {**files, PurePosixPath("package.json"): b"{}"},
        "user config": {
            **files,
            plugin.MANIFEST: json.dumps({**json.loads(files[plugin.MANIFEST]), "userConfig": {}}).encode(),
        },
        "short readme": {**files, PurePosixPath("README.md"): b"Too short.\n```\n" + b"word " * 100 + b"\n```\n"},
        "case clash": {**files, PurePosixPath("readme.md"): b"x"},
        "windows name": {**files, PurePosixPath("skills/con.md"): b"x"},
    }
    for label, tree in broken.items():
        assert build.audit(sorted(tree.items(), key=lambda item: str(item[0]))), label


def test_hooks_run_only_python3_on_the_bundled_script() -> None:
    config = json.loads(FILES["hooks/hooks.json"])
    commands = {hook["command"] for groups in config["hooks"].values() for g in groups for hook in g["hooks"]}
    assert commands
    for command in commands:
        assert re.fullmatch(r'python3 "\$\{CLAUDE_PLUGIN_ROOT\}/hooks/kestrix_hook\.py" [a-z-]+', command)


def test_no_secrets_and_no_hardcoded_home_paths(tmp_path: Path) -> None:
    out = tmp_path / "repo"
    build.write(out, TREE)
    report = scan([out], root=out)
    assert [f for f in report.findings if f.rule_id.startswith("secret.")] == []
    assert not [name for name, data in FILES.items() if re.search(rb"/Users/|/home/[a-z]", data)]


def test_readme_covers_what_the_directory_asks_for() -> None:
    readme = _text("README.md")
    assert build._readme_words(readme) >= build.MIN_README_WORDS
    for needle in (
        "pip install kestrix-scan",
        "uv tool install kestrix-scan",
        "pipx install kestrix-scan",
        "never installs anything",
        "fails open",
        "kestrix-scan db update",
        "KESTRIX_BLOCK_ON_STOP=1",
        '{"claude": {"block_on_stop": true}}',
        "PRIVACY.md",
        "Apache-2.0",
        "no `userConfig`",
        "security-guidance",
    ):
        assert needle in readme, needle
    for event in ("SessionStart", "PreToolUse", "PostToolUse", "Stop"):
        assert f"`{event}" in readme, event


def test_privacy_points_at_a_test_that_ships_in_the_repository() -> None:
    privacy = _text("PRIVACY.md")
    assert "tests/test_no_network.py" in privacy and "tests/test_no_network.py" in FILES
    assert "no telemetry" in privacy.lower().replace("**", "")


def test_security_policy_uses_private_reporting_for_this_repository() -> None:
    assert f"{build.REPO_URL}/security/advisories/new" in _text("SECURITY.md")


def test_the_shipped_no_network_test_passes(tmp_path: Path) -> None:
    out = tmp_path / "repo"
    build.write(out, TREE)
    env = {**os.environ, "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])}
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=out,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "skipped" not in result.stderr and "Ran 2 tests" in result.stderr


def test_eval_cases_are_complete() -> None:
    cases = sorted(
        {
            name.removesuffix("/prompt.md").removeprefix("evals/")
            for name in FILES
            if name.startswith("evals/") and name.endswith("/prompt.md")
        }
    )
    assert len(cases) >= 4 + 13  # the smoke cases and the A/B suite under evals/ab/
    for case in cases:
        prompt = _text(f"evals/{case}/prompt.md")
        assert prompt.startswith("---\n") and "\n---\n" in prompt[4:]
        assert [n for n in FILES if n.startswith(f"evals/{case}/graders/") and n.endswith(".md")], case


def test_write_keeps_git_and_refuses_unrelated_directories(tmp_path: Path) -> None:
    out = tmp_path / "repo"
    (out / ".git").mkdir(parents=True)
    (out / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    build.write(out, TREE)
    build.write(out, TREE)
    assert (out / ".git" / "HEAD").read_text() == "ref: refs/heads/main\n"
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("mine")
    with pytest.raises(SystemExit, match="refusing"):
        build.write(other, TREE)
    link = tmp_path / "link"
    link.symlink_to(out)
    with pytest.raises(SystemExit, match="symbolic link"):
        build.write(link, TREE)


# ----- README claims that must not drift


def _registry_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for rule in registry_rules():
        family = rule.id.split(".")[0]
        family = "web" if family in {"vue", "svelte", "web", "html", "css", "next"} else family
        counts[family] = counts.get(family, 0) + 1
    return counts


def test_readme_rule_counts_match_the_registry() -> None:
    counts = _registry_counts()
    total = sum(counts.values())
    readme = _text("README.md")
    stated = re.search(
        r"(\d+) rules in all, (\d+) Python, (\d+) JS/TS, (\d+) web-file, (\d+) secret, (\d+) dependency, (\d+) agent-config rules",
        readme,
    )
    assert stated, "README.md must state the rule count per family"
    expected = (total, counts["py"], counts["js"], counts["web"], counts["secret"], counts["dep"], counts["config"])
    assert tuple(int(n) for n in stated.groups()) == expected
    # no other count of rules anywhere in the README, and the rule-counting sentences name the same numbers
    assert {int(n) for n in re.findall(r"(\d+) rules in all", readme)} == {total}
    assert {int(n) for n in re.findall(r"\b(\d+) rules\b", readme)} <= {total}
    assert "{{" not in readme


def test_other_docs_state_the_same_rule_counts() -> None:
    counts = _registry_counts()
    total = sum(counts.values())
    scan_readme = (REPO / "packages/kestrix-scan/README.md").read_text(encoding="utf-8")
    assert f"There are {total} rules." in scan_readme
    for family in ("py", "js", "config", "secret", "dep"):
        found = re.findall(rf"\((\d+) `{family}\.\*`\s+rules|(\d+) `{family}\.\*`\s+rules", scan_readme)
        assert found, family
        assert {int(a or b) for a, b in found} == {counts[family]}, family
    doc = (REPO / "docs/claude-plugin.md").read_text(encoding="utf-8")
    assert (
        f"{total} rules in all: {counts['py']} Python, {counts['js']} JS/TS, {counts['web']} web-file, {counts['secret']} secret,"
        in doc
    )
    assert f"{counts['dep']} dependency, {counts['config']} agent-config rules" in doc
    submission = (REPO / "docs/plugin-submission.md").read_text(encoding="utf-8")
    assert {int(n) for n in re.findall(r"Its (\d+) rules", submission)} == {total}


def test_readme_example_is_the_real_hook_output() -> None:
    readme = _text("README.md")
    block = readme.split("```text\n", 1)[1].split("\n```", 1)[0]
    assert block == build.readme_example()
    assert "(CWE-78)" in block and 'subprocess.run(f"ls {path}", shell=True)' in block
    assert block.rstrip().endswith('subprocess.run(["ls", path], check=True)')


def test_readme_privacy_coverage_and_does_it_help_say_what_they_must() -> None:
    readme = _text("README.md")

    def section(title: str, nth: int = 0) -> str:
        body = readme.split(f"\n## {title}\n", 1)[1].split("\n## ", 1)[0]
        return " ".join(body.split("\n\n")[nth].split()) if nth >= 0 else " ".join(body.split())

    privacy = section("Privacy", 0)  # the first paragraph
    assert "local and makes no network calls" in privacy
    assert "sent to Anthropic like any other conversation content" in privacy
    assert "Secret values are never included" in privacy
    coverage = section("Coverage", -1)
    for phrase in (
        "`Write`, `Edit`, `MultiEdit` and `NotebookEdit`",
        "Bash command",
        "git",
        "Analysis is per file",
        "tracked within one function",
        "no whole-program or cross-file analysis",
        "secrets in any text file",
        "dependency lockfiles",
        "kestrix-scan db update",
        "No findings is not proof of security",
    ):
        assert phrase in coverage, phrase
    helps = section("Does it help?", -1)
    assert "benchmarks/scorecard.md" in helps and "**not blind**" in helps
    assert "benchmarks/plugin-ab.md" in helps and 'reads "not yet run"' in helps
    assert "no effectiveness number" in helps.lower()


def test_benchmark_pages_ship_without_links_into_the_private_repository() -> None:
    scorecard, report = _text("benchmarks/scorecard.md"), _text("benchmarks/plugin-ab.md")
    assert "Disclosure: this round of rule changes was informed by the benchmark" in scorecard
    assert "[bench/run.py]" not in scorecard and "](../../" not in scorecard + report
    assert "**Status: not yet run. No effectiveness numbers are claimed.**" in report
    assert "<!-- results:start -->" in report and "Not yet run." in report


def test_secure_review_description_is_third_person_with_trigger_phrases() -> None:
    text = _text("skills/secure-code-review/SKILL.md")
    description = re.search(r"^description: (.*)$", text, re.M)
    assert description
    value = description.group(1)
    assert len(value) <= 1024
    assert value.startswith("Reviews ") and not re.search(r"\b(I|you|your)\b", value)
    for phrase in ("review this for security", "is this code safe", "check for vulnerabilities", "Use when"):
        assert phrase in value, phrase
