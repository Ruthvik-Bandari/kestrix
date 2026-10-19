# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Install, remove and package the bundled ``kestrix-security`` Claude skill.

The skill is plain package data (Markdown). Its one source is the Claude Code plugin's
``skills/kestrix-security/`` folder, so the plugin and this installer never drift apart.
Installing copies it into a fresh directory; it never writes through a symlink and only ever
replaces or removes a directory that already holds this skill. ``plugin.py`` reuses the
same tree and zip writers.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable, Iterator, Sequence
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath

SKILL_NAME = "kestrix-security"
_MARKER = f"name: {SKILL_NAME}"
# Fixed timestamp and modes keep the zip byte-identical across builds and machines.
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
_FILE_MODE = 0o644
_DIR_MODE = 0o755


class SkillError(Exception):
    """Raised when an install, uninstall or package request is refused."""


def default_dest() -> Path:
    return Path.home() / ".claude" / "skills" / SKILL_NAME


def skill_source() -> Traversable:
    return files("kestrix.integrations") / "claude_plugin" / "kestrix" / "skills" / SKILL_NAME


def skill_files() -> list[tuple[PurePosixPath, bytes]]:
    """Every file of the packaged skill as (relative path, bytes), sorted by path."""
    found = sorted(walk_files(skill_source(), PurePosixPath()), key=lambda item: str(item[0]))
    if not any(path == PurePosixPath("SKILL.md") for path, _ in found):
        raise SkillError("the packaged skill is missing SKILL.md; reinstall kestrix")
    return found


def walk_files(
    node: Traversable, prefix: PurePosixPath, keep: frozenset[str] = frozenset()
) -> Iterator[tuple[PurePosixPath, bytes]]:
    """Files under ``node``, skipping hidden names (except those in ``keep``) and ``__pycache__``."""
    for child in node.iterdir():
        if (child.name.startswith(".") and child.name not in keep) or child.name == "__pycache__":
            continue
        rel = prefix / child.name
        if child.is_dir():
            yield from walk_files(child, rel, keep)
        else:
            yield rel, child.read_bytes()


def _holds_this_skill(path: Path) -> bool:
    skill_md = path / "SKILL.md"
    if skill_md.is_symlink() or not skill_md.is_file():
        return False
    head = skill_md.read_text(encoding="utf-8", errors="replace")[:2048]
    return head.startswith("---") and _MARKER in head.splitlines()


def _check_replaceable(dest: Path, holds: Callable[[Path], bool], what: str) -> None:
    """Refuse a destination that is a symlink, a file, or a directory holding something else."""
    if dest.is_symlink():
        raise SkillError(f"{dest} is a symbolic link; refusing to follow it")
    if not dest.exists():
        return
    if not dest.is_dir():
        raise SkillError(f"{dest} exists and is not a directory")
    if any(dest.iterdir()) and not holds(dest):
        raise SkillError(f"{dest} is not empty and does not hold {what}; refusing to replace it")


def install(dest: Path | None = None, *, force: bool = False) -> Path:
    """Copy the skill to ``dest`` (default ``~/.claude/skills/kestrix-security``) and return its path."""
    target = Path(os.path.abspath(dest if dest is not None else default_dest()))
    return install_tree(target, skill_files(), holds=_holds_this_skill, what=f"the {SKILL_NAME} skill", force=force)


def install_tree(
    target: Path,
    content: Sequence[tuple[PurePosixPath, bytes]],
    *,
    holds: Callable[[Path], bool],
    what: str,
    force: bool,
) -> Path:
    """Write ``content`` into ``target`` through a staging sibling; replace only what ``holds`` recognizes."""
    _check_replaceable(target, holds, what)
    if target.exists() and not force:
        raise SkillError(f"{target} already exists; pass --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}-", dir=target.parent))
    try:
        for rel, data in content:
            out = staging.joinpath(*rel.parts)
            out.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
            out.write_bytes(data)
            out.chmod(_FILE_MODE)
        staging.chmod(_DIR_MODE)
        if target.exists():
            # rmtree removes symlinks found inside the old copy without following them.
            shutil.rmtree(target)
        staging.rename(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def uninstall(dest: Path | None = None) -> Path:
    """Remove an installed copy of the skill and return the path that was removed."""
    target = Path(os.path.abspath(dest if dest is not None else default_dest()))
    if target.is_symlink():
        raise SkillError(f"{target} is a symbolic link; refusing to follow it")
    if not target.exists():
        raise SkillError(f"{target} does not exist; nothing to remove")
    if not target.is_dir() or not _holds_this_skill(target):
        raise SkillError(f"{target} does not hold the {SKILL_NAME} skill; refusing to remove it")
    shutil.rmtree(target)
    return target


def package(out: Path, *, force: bool = False) -> Path:
    """Write a deterministic zip with the skill folder at its root, for upload to Claude.ai or Desktop."""
    target = Path(os.path.abspath(out))
    if target.is_symlink():
        raise SkillError(f"{target} is a symbolic link; refusing to follow it")
    if target.exists() and (target.is_dir() or not force):
        raise SkillError(f"{target} already exists; pass --force to replace it")
    return write_zip(target, PurePosixPath(SKILL_NAME), skill_files())


def write_zip(target: Path, root: PurePosixPath | None, content: Sequence[tuple[PurePosixPath, bytes]]) -> Path:
    """Write ``content`` as a deterministic zip, inside the folder ``root`` or, when it is None, at the top level."""
    top = root if root is not None else PurePosixPath()
    parents = {str(top / parent) + "/" for rel, _ in content for parent in [*rel.parents][:-1]}
    dirs = sorted(parents | {f"{root}/"} if root is not None else parents)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".kestrix-skill-", suffix=".zip", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle, zipfile.ZipFile(handle, "w") as archive:
            for name in dirs:
                info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
                info.external_attr = (0o40000 | _DIR_MODE) << 16
                archive.writestr(info, b"")
            for rel, data in content:
                info = zipfile.ZipInfo(str(top / rel), date_time=_ZIP_DATE)
                info.external_attr = (0o100000 | _FILE_MODE) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data, compresslevel=9)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target
