# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Installing and zipping the Claude Code plugin stays inside the destination it is given."""

import json
import zipfile
from pathlib import Path

import pytest
from cli_support import run

from kestrix_scan import plugin
from kestrix_scan.skill import SkillError

PACKAGED = {str(path): data for path, data in plugin.plugin_files()}


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root).as_posix()): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_install_copies_every_file_and_prints_the_enable_commands(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-plugin"
    result = run("install-claude-plugin", "--dest", str(dest))
    assert result.exit_code == 0, result.output
    assert _tree(dest) == PACKAGED
    assert {".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "hooks/hooks.json"} <= PACKAGED.keys()
    assert "skills/kestrix-security/SKILL.md" in PACKAGED
    assert not any("__pycache__" in name for name in PACKAGED)
    assert f"claude plugin marketplace add {dest}" in result.stdout
    assert "claude plugin install kestrix@kestrix-local" in result.stdout
    assert f"/plugin marketplace add {dest}" in result.stdout
    assert f"claude --plugin-dir {dest}" in result.stdout
    assert not [p for p in dest.parent.iterdir() if p.name.startswith(".")]  # no staging left behind


def test_default_destination_never_touches_claude_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert plugin.default_dest() == tmp_path / ".claude" / "kestrix-plugin"
    assert plugin.install() == tmp_path / ".claude" / "kestrix-plugin"
    assert sorted(p.name for p in (tmp_path / ".claude").iterdir()) == ["kestrix-plugin"]


def test_existing_install_needs_force(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-plugin"
    plugin.install(dest)
    (dest / "stale.md").write_text("old")
    result = run("install-claude-plugin", "--dest", str(dest))
    assert result.exit_code == 2
    assert "pass --force" in result.stderr
    assert (dest / "stale.md").exists()
    result = run("install-claude-plugin", "--dest", str(dest), "--force")
    assert result.exit_code == 0, result.output
    assert _tree(dest) == PACKAGED


def test_force_never_replaces_an_unrelated_directory(tmp_path: Path) -> None:
    dest = tmp_path / "projects"
    (dest / ".claude-plugin").mkdir(parents=True)
    (dest / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "someone-else"}))
    result = run("install-claude-plugin", "--dest", str(dest), "--force")
    assert result.exit_code == 2
    assert "does not hold the kestrix plugin" in result.stderr
    assert json.loads((dest / ".claude-plugin" / "plugin.json").read_text()) == {"name": "someone-else"}


def test_symlinked_destination_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    plugin.install(outside)
    link = tmp_path / "kestrix-plugin"
    link.symlink_to(outside, target_is_directory=True)
    result = run("install-claude-plugin", "--dest", str(link), "--force")
    assert result.exit_code == 2
    assert "symbolic link" in result.stderr
    assert _tree(outside) == PACKAGED


def test_symlinked_manifest_does_not_count_as_this_plugin(tmp_path: Path) -> None:
    real = plugin.install(tmp_path / "real")
    dest = tmp_path / "kestrix-plugin"
    (dest / ".claude-plugin").mkdir(parents=True)
    (dest / ".claude-plugin" / "plugin.json").symlink_to(real / ".claude-plugin" / "plugin.json")
    with pytest.raises(SkillError, match="does not hold"):
        plugin.install(dest, force=True)
    linked = tmp_path / "linked-dir"
    linked.mkdir()
    (linked / ".claude-plugin").symlink_to(real / ".claude-plugin", target_is_directory=True)
    with pytest.raises(SkillError, match="does not hold"):
        plugin.install(linked, force=True)


def test_force_replace_does_not_follow_symlinks_inside_the_old_copy(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "data.txt").write_text("precious")
    dest = plugin.install(tmp_path / "kestrix-plugin")
    (dest / "skills" / "escape").symlink_to(victim, target_is_directory=True)
    plugin.install(dest, force=True)
    assert (victim / "data.txt").read_text() == "precious"
    assert _tree(dest) == PACKAGED


def test_package_writes_a_deterministic_zip(tmp_path: Path) -> None:
    first, second = tmp_path / "a.zip", tmp_path / "sub" / "b.zip"
    result = run("package-claude-plugin", "--out", str(first))
    assert result.exit_code == 0, result.output
    assert str(first) in result.stdout
    plugin.package(second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names, key=lambda n: (not n.endswith("/"), n))
        assert ".claude-plugin/plugin.json" in names  # the plugin root is the zip root
        assert not any(name.startswith(("/", "./", "../")) for name in names)
        assert {n: archive.read(n) for n in names if not n.endswith("/")} == PACKAGED
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_package_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "plugin.zip"
    out.write_bytes(b"old")
    result = run("package-claude-plugin", "--out", str(out))
    assert result.exit_code == 2
    assert out.read_bytes() == b"old"
    assert run("package-claude-plugin", "--out", str(out), "--force").exit_code == 0
    assert zipfile.is_zipfile(out)
    link = tmp_path / "link.zip"
    link.symlink_to(out)
    with pytest.raises(plugin.PluginError, match="symbolic link"):
        plugin.package(link, force=True)
