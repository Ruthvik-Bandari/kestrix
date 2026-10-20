# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Installing, removing and zipping the Claude skill stays inside the destination it is given."""

import zipfile
from pathlib import Path

import pytest
from cli_support import run

from kestrix_scan import skill

PACKAGED = {str(path): data for path, data in skill.skill_files()}


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root).as_posix()): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_install_copies_every_file(tmp_path: Path) -> None:
    dest = tmp_path / "skills" / "kestrix-security"
    result = run("install-claude-skill", "--dest", str(dest))
    assert result.exit_code == 0, result.output
    assert str(dest) in result.stdout
    assert _tree(dest) == PACKAGED
    assert {"SKILL.md", "reference/findings-mail.md", "reference/json-fields.md"} <= PACKAGED.keys()
    assert not [p for p in dest.parent.iterdir() if p.name.startswith(".")]  # no staging left behind


def test_default_destination_is_under_the_home_claude_skills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert skill.default_dest() == tmp_path / ".claude" / "skills" / "kestrix-security"
    assert skill.install() == tmp_path / ".claude" / "skills" / "kestrix-security"
    assert (tmp_path / ".claude" / "skills" / "kestrix-security" / "SKILL.md").is_file()


def test_existing_install_needs_force(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-security"
    skill.install(dest)
    (dest / "SKILL.md").write_text((dest / "SKILL.md").read_text() + "\nlocal edit\n")
    (dest / "stale.md").write_text("old")
    result = run("install-claude-skill", "--dest", str(dest))
    assert result.exit_code == 2
    assert "pass --force" in result.stderr
    assert "local edit" in (dest / "SKILL.md").read_text()
    result = run("install-claude-skill", "--dest", str(dest), "--force")
    assert result.exit_code == 0, result.output
    assert _tree(dest) == PACKAGED


def test_empty_existing_directory_is_used_without_force(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-security"
    dest.mkdir()
    with pytest.raises(skill.SkillError, match="--force"):
        skill.install(dest)
    assert skill.install(dest, force=True) == dest
    assert _tree(dest) == PACKAGED


def test_force_never_replaces_an_unrelated_directory(tmp_path: Path) -> None:
    dest = tmp_path / "projects"
    dest.mkdir()
    (dest / "notes.txt").write_text("keep me")
    result = run("install-claude-skill", "--dest", str(dest), "--force")
    assert result.exit_code == 2
    assert "does not hold the kestrix-security skill" in result.stderr
    assert (dest / "notes.txt").read_text() == "keep me"


def test_file_destination_is_refused(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-security"
    dest.write_text("a file")
    with pytest.raises(skill.SkillError, match="not a directory"):
        skill.install(dest, force=True)


def test_symlinked_destination_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    skill.install(outside)
    link = tmp_path / "kestrix-security"
    link.symlink_to(outside, target_is_directory=True)
    for argv in (["install-claude-skill", "--force"], ["uninstall-claude-skill"]):
        result = run(*argv, "--dest", str(link))
        assert result.exit_code == 2
        assert "symbolic link" in result.stderr
    assert _tree(outside) == PACKAGED


def test_force_replace_does_not_follow_symlinks_inside_the_old_copy(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "data.txt").write_text("precious")
    dest = tmp_path / "kestrix-security"
    skill.install(dest)
    (dest / "reference" / "escape").symlink_to(victim, target_is_directory=True)
    skill.install(dest, force=True)
    assert (victim / "data.txt").read_text() == "precious"
    assert _tree(dest) == PACKAGED


def test_symlinked_skill_md_does_not_count_as_this_skill(tmp_path: Path) -> None:
    real = tmp_path / "real"
    skill.install(real)
    dest = tmp_path / "kestrix-security"
    dest.mkdir()
    (dest / "SKILL.md").symlink_to(real / "SKILL.md")
    with pytest.raises(skill.SkillError, match="does not hold"):
        skill.install(dest, force=True)


def test_uninstall_removes_only_this_skill(tmp_path: Path) -> None:
    dest = tmp_path / "kestrix-security"
    skill.install(dest)
    result = run("uninstall-claude-skill", "--dest", str(dest))
    assert result.exit_code == 0, result.output
    assert not dest.exists()
    result = run("uninstall-claude-skill", "--dest", str(dest))
    assert result.exit_code == 2
    assert "nothing to remove" in result.stderr
    other = tmp_path / "other"
    other.mkdir()
    (other / "SKILL.md").write_text("---\nname: something-else\n---\n")
    with pytest.raises(skill.SkillError, match="does not hold"):
        skill.uninstall(other)
    assert (other / "SKILL.md").exists()


def test_package_writes_a_deterministic_zip(tmp_path: Path) -> None:
    first, second = tmp_path / "a.zip", tmp_path / "sub" / "b.zip"
    result = run("package-claude-skill", "--out", str(first))
    assert result.exit_code == 0, result.output
    assert str(first) in result.stdout
    skill.package(second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names, key=lambda n: (not n.endswith("/"), n))
        assert "kestrix-security/SKILL.md" in names
        assert all(n.startswith("kestrix-security/") for n in names)
        files = {n.removeprefix("kestrix-security/"): archive.read(n) for n in names if not n.endswith("/")}
        assert files == PACKAGED
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_package_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "skill.zip"
    out.write_bytes(b"old")
    result = run("package-claude-skill", "--out", str(out))
    assert result.exit_code == 2
    assert out.read_bytes() == b"old"
    assert run("package-claude-skill", "--out", str(out), "--force").exit_code == 0
    assert zipfile.is_zipfile(out)
    link = tmp_path / "link.zip"
    link.symlink_to(out)
    with pytest.raises(skill.SkillError, match="symbolic link"):
        skill.package(link, force=True)
