# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The plugin manifest, marketplaces, hooks and skills are well formed and agree with the package."""

import importlib.util
import json
import re
import tomllib
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

import pytest

import kestrix
from kestrix.code.python_rules import check_python
from kestrix.code.rules import RULES
from kestrix.integrations import plugin

REPO = Path(__file__).resolve().parents[2]
FILES = {str(path): data for path, data in plugin.plugin_files()}
SKILLS = sorted({path.split("/")[1] for path in FILES if path.startswith("skills/")})
COMMANDS = {"scan", "fix", "review"}
# Frontmatter keys documented for skills at https://code.claude.com/docs/en/skills
SKILL_KEYS = {"name", "description", "argument-hint", "disable-model-invocation", "allowed-tools", "when_to_use"}


def _json(path: str) -> Any:
    return json.loads(FILES[path])


def _frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, "SKILL.md must start with a --- frontmatter block"
    fields = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(":")
        assert sep and re.fullmatch(r"[a-z_-]+", key), f"unexpected frontmatter line: {line!r}"
        fields[key] = value.strip()
    return fields


def test_plugin_manifest_has_the_required_fields() -> None:
    manifest = _json(".claude-plugin/plugin.json")
    assert manifest["name"] == plugin.PLUGIN_NAME
    assert manifest["version"] == kestrix.__version__
    assert manifest["author"]["name"] == "Ruthvik Bandari"
    assert manifest["homepage"] == manifest["repository"] == "https://github.com/Ruthvik-Bandari/kestrix"
    assert manifest["license"] == "Apache-2.0"
    assert manifest["description"] and manifest["keywords"]
    assert {path.split("/")[0] for path in FILES} == {".claude-plugin", "hooks", "skills"}


def test_versions_match_everywhere() -> None:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    repo_market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    local_market = _json(".claude-plugin/marketplace.json")
    versions = {
        kestrix.__version__,
        pyproject,
        _json(".claude-plugin/plugin.json")["version"],
        repo_market["plugins"][0]["version"],
        local_market["plugins"][0]["version"],
    }
    assert versions == {kestrix.__version__}


def _check_marketplace(market: dict[str, Any], root: Path) -> None:
    assert re.fullmatch(r"[a-z0-9][a-z0-9._-]*", market["name"])
    assert market["owner"]["name"] == "Ruthvik Bandari"
    (entry,) = market["plugins"]
    assert entry["name"] == plugin.PLUGIN_NAME
    source = entry["source"]
    assert source.startswith("./") and ".." not in PurePosixPath(source).parts
    manifest = root / source / ".claude-plugin" / "plugin.json"
    assert json.loads(manifest.read_text())["name"] == plugin.PLUGIN_NAME


def test_repo_marketplace_points_at_the_plugin_directory() -> None:
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    assert market["name"] == "kestrix"
    _check_marketplace(market, REPO)
    assert (REPO / market["plugins"][0]["source"]).resolve() == Path(str(plugin.plugin_source())).resolve()


def test_installed_copy_is_a_local_marketplace(tmp_path: Path) -> None:
    dest = plugin.install(tmp_path / "kestrix-plugin")
    market = json.loads((dest / ".claude-plugin" / "marketplace.json").read_text())
    assert market["name"] == plugin.LOCAL_MARKETPLACE
    assert market["plugins"][0]["source"] == "./"
    _check_marketplace(market, dest)


def _hook_commands() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    config = _json("hooks/hooks.json")
    assert set(config) == {"hooks"}
    return [
        (event, group, hook) for event, groups in config["hooks"].items() for group in groups for hook in group["hooks"]
    ]


def test_hooks_cover_the_documented_events_and_tools() -> None:
    commands = _hook_commands()
    assert {event for event, _, _ in commands} == {"SessionStart", "PostToolUse", "Stop"}
    (post,) = [group for event, group, _ in commands if event == "PostToolUse"]
    assert set(post["matcher"].split("|")) == {"Write", "Edit", "MultiEdit", "NotebookEdit"}
    timeouts = {event: hook["timeout"] for event, _, hook in commands}
    assert timeouts["PostToolUse"] <= 10 and timeouts["SessionStart"] <= 10 and timeouts["Stop"] <= 60


def test_hooks_run_only_files_inside_the_plugin() -> None:
    script = FILES["hooks/kestrix_hook.py"].decode()
    for _, _, hook in _hook_commands():
        assert hook["type"] == "command"
        match = re.fullmatch(r'python3 "\$\{CLAUDE_PLUGIN_ROOT\}/([^"]+)" ([a-z-]+)', hook["command"])
        assert match, hook["command"]
        assert match.group(1) in FILES
        assert f'event == "{match.group(2)}"' in script


@pytest.mark.parametrize("name", SKILLS)
def test_skill_frontmatter_is_valid(name: str) -> None:
    text = FILES[f"skills/{name}/SKILL.md"].decode()
    fields = _frontmatter(text)
    assert set(fields) <= SKILL_KEYS
    assert fields["name"] == name
    assert len(name) <= 64 and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name)
    assert 0 < len(fields["description"]) <= 1024
    assert "<" not in fields["description"] and ">" not in fields["description"]
    if name in COMMANDS:
        assert fields["disable-model-invocation"] == "true"
        assert fields["argument-hint"].startswith('"[')
        assert "$ARGUMENTS" in text
    else:
        assert "disable-model-invocation" not in fields


def test_the_plugin_ships_the_expected_skills() -> None:
    assert set(SKILLS) == {"secure-code-review", "fixing-security-findings", "kestrix-security", *COMMANDS}


@pytest.mark.parametrize("name", ["secure-code-review", "fix", "review", "scan"])
def test_skills_treat_code_as_data(name: str) -> None:
    text = FILES[f"skills/{name}/SKILL.md"].decode()
    assert re.search(r"(is|are) data", text)
    assert "secret" in text.lower()


def test_secure_code_review_covers_every_rule() -> None:
    text = FILES["skills/secure-code-review/SKILL.md"].decode()
    python_ids = {rule.id for rule in RULES.values() if rule.language == "python"}
    assert python_ids <= set(re.findall(r"`(py\.[a-z_.]+)`", text))
    assert "`secret.*`" in text
    assert "fixing-security-findings" in text


# ----- the generated fix playbook


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_claude_fix_playbook", REPO / "scripts" / "build_claude_fix_playbook.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fix_playbook_matches_the_registry(generator: ModuleType) -> None:
    text = FILES["skills/fixing-security-findings/SKILL.md"].decode()
    assert text == generator.render(), "run: uv run python scripts/build_claude_fix_playbook.py"
    assert re.findall(r"^### `([a-z_.]+)`", text, re.M) == list(RULES)
    for rule in RULES.values():
        assert rule.fix in text and rule.why in text and rule.cwe in text


def test_fix_playbook_check_mode(generator: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("sys.argv", ["build", "--check"])
    assert generator.main() == 0
    stale = tmp_path / "SKILL.md"
    stale.write_text("old")
    monkeypatch.setattr(generator, "SKILL", stale)
    assert generator.main() == 1
    assert stale.read_text() == "old"


@pytest.mark.parametrize("rule_id", [rule.id for rule in RULES.values() if rule.language == "python"])
def test_fix_playbook_examples_fire_before_and_not_after(generator: ModuleType, rule_id: str) -> None:
    before, after = generator.EXAMPLES[rule_id]
    before_hits = check_python(before, "app.py")
    after_hits = check_python(after, "app.py")
    assert isinstance(before_hits, list) and isinstance(after_hits, list)
    assert rule_id in {hit.rule_id for hit in before_hits}
    assert after_hits == []


def test_fix_playbook_refuses_a_rule_without_an_example(generator: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(generator.EXAMPLES, "py.exec.eval")
    with pytest.raises(SystemExit, match=r"missing \['py.exec.eval'\]"):
        generator.render()
