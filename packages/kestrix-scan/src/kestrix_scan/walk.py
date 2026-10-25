# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Collect the files to scan under a root, read them as bytes and decode them as text.

Directory traversal skips version-control, dependency and build directories, and honors
``.gitignore``: through ``git ls-files`` when the root is inside a git work tree, otherwise
through a small parser for the root ``.gitignore`` (globs, ``**``, directory patterns,
anchoring, negation and comments). A file named explicitly is scanned even when it is ignored.
Symbolic links are never followed out of the root; links to directories are not followed at all.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .lockfiles import MAX_LOCKFILE_BYTES, parser_for
from .models import SkippedFile, SkipReason

MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 20_000
BINARY_PROBE_BYTES = 8192
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        ".venv",
        "venv",
        "dist",
        "build",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        "site-packages",
        "vendor",
        "third_party",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".output",
        ".angular",
        ".terraform",
        "target",
        ".gradle",
        "obj",
    }
)
_GIT_TIMEOUT_S = 10


@dataclass(frozen=True)
class Candidate:
    path: Path  # absolute
    rel: str  # relative to the root, posix


@dataclass
class Walk:
    candidates: list[Candidate] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    truncated: bool = False


def rel_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def collect(paths: Sequence[Path], root: Path) -> Walk:
    """Files under ``paths`` (absolute, inside ``root``), with skipped files and the file-limit flag."""
    walk = Walk()
    seen: set[Path] = set()
    listed = False  # git and .gitignore are consulted only when a directory is walked
    allowed: frozenset[str] | None = None
    ignore: _GitIgnore | None = None
    for start in paths:
        if walk.truncated:
            break
        if start.is_dir() and not start.is_symlink():
            if not listed:
                listed = True
                allowed = _git_files(root)
                ignore = None if allowed is not None else _GitIgnore.from_root(root)
            files: Iterable[Path] = _walk_dir(start, root, allowed, ignore, walk)
        else:
            files = [start]
        for path in files:
            if len(walk.candidates) >= MAX_FILES:
                walk.truncated = True
                break
            _consider(path, root, seen, walk)
    return walk


def _consider(path: Path, root: Path, seen: set[Path], walk: Walk) -> None:
    rel = rel_path(path, root)
    try:
        info = path.lstat()
    except OSError:
        walk.skipped.append(SkippedFile(path=rel, reason="unreadable"))
        return
    real = path
    if stat.S_ISLNK(info.st_mode):
        real = path.resolve()
        if not is_within(real, root):
            walk.skipped.append(SkippedFile(path=rel, reason="symlink_outside_root"))
            return
        try:
            info = real.stat()
        except OSError:
            walk.skipped.append(SkippedFile(path=rel, reason="unreadable"))
            return
        rel = rel_path(real, root)  # report the file where it lives, once
    if not stat.S_ISREG(info.st_mode) or real in seen:
        return
    seen.add(real)
    if info.st_size > file_limit(rel):
        walk.skipped.append(SkippedFile(path=rel, reason="too_large"))
        return
    walk.candidates.append(Candidate(path=real, rel=rel))


def _walk_dir(
    start: Path, root: Path, allowed: frozenset[str] | None, ignore: _GitIgnore | None, walk: Walk
) -> Iterable[Path]:
    allowed_dirs = _parents(allowed) if allowed is not None else None
    for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
        here = Path(dirpath)
        here_rel = "" if here == root else rel_path(here, root)
        keep = []
        for name in sorted(dirnames):
            child_rel = f"{here_rel}/{name}" if here_rel else name
            child = here / name
            if name in SKIP_DIRS:
                continue
            if child.is_symlink():
                if not is_within(child.resolve(), root):
                    walk.skipped.append(SkippedFile(path=child_rel, reason="symlink_outside_root"))
                continue
            if allowed_dirs is not None and child_rel not in allowed_dirs:
                continue
            if ignore is not None and ignore.ignored(child_rel, is_dir=True):
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            file_rel = f"{here_rel}/{name}" if here_rel else name
            if allowed is not None and file_rel not in allowed:
                continue
            if ignore is not None and ignore.ignored(file_rel, is_dir=False):
                continue
            yield here / name


def _parents(files: frozenset[str]) -> frozenset[str]:
    dirs: set[str] = set()
    for name in files:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return frozenset(dirs)


def git_executable() -> str | None:
    return shutil.which("git")


def _git_files(root: Path) -> frozenset[str] | None:
    """Tracked and untracked-but-not-ignored files under ``root``, or None outside a git work tree."""
    git = git_executable()
    if git is None:
        return None
    try:
        out = subprocess.run(  # noqa: S603 - git from PATH with a fixed argument list, no shell
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return frozenset(name for name in out.stdout.decode("utf-8", "replace").split("\0") if name)


def file_limit(rel: str) -> int:
    """The size cap for a file: lockfiles may be up to 64 MiB, everything else 1 MiB."""
    return MAX_LOCKFILE_BYTES if parser_for(rel) is not None else MAX_FILE_BYTES


class Unreadable(Exception):
    def __init__(self, reason: SkipReason) -> None:
        super().__init__(reason)
        self.reason: SkipReason = reason


def read_text(candidate: Candidate, limit: int = MAX_FILE_BYTES) -> str:
    """Decoded text of the file (UTF-8, invalid bytes replaced). Raises ``Unreadable`` with the skip reason."""
    try:
        with candidate.path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise Unreadable("unreadable") from None
    if len(data) > limit:
        raise Unreadable("too_large")
    if b"\0" in data[:BINARY_PROBE_BYTES]:
        raise Unreadable("binary")
    return data.decode("utf-8", errors="replace")


class _GitIgnore:
    """The subset of gitignore semantics used when git is not available.

    Supported: blank lines and ``#`` comments, ``!`` negation (the last matching pattern wins),
    a trailing ``/`` for directories only, patterns with an inner or leading ``/`` anchored to the
    root, other patterns matched against the name at any depth, and ``*``, ``?``, ``[...]`` and ``**``.
    Only the root ``.gitignore`` is read. As in git, a file inside an ignored directory stays
    ignored because the directory is never entered.
    """

    def __init__(self, patterns: list[tuple[re.Pattern[str], bool, bool, bool]]) -> None:
        self._patterns = patterns  # (regex, negated, dir_only, anchored)

    @classmethod
    def from_root(cls, root: Path) -> _GitIgnore:
        try:
            text = (root / ".gitignore").read_bytes()[:MAX_FILE_BYTES].decode("utf-8", "replace")
        except OSError:
            return cls([])
        return cls.parse(text)

    @classmethod
    def parse(cls, text: str) -> _GitIgnore:
        patterns = []
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:]
            if line.startswith("\\"):
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            line = line.lstrip("/")
            patterns.append((re.compile(_glob_regex(line)), negated, dir_only, anchored))
        return cls(patterns)

    def ignored(self, rel: str, *, is_dir: bool) -> bool:
        result = False
        name = rel.rsplit("/", 1)[-1]
        for regex, negated, dir_only, anchored in self._patterns:
            if dir_only and not is_dir:
                continue
            if regex.fullmatch(rel if anchored else name):
                result = not negated
        return result


def _glob_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**", i):
            if pattern.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            else:
                out.append(".*")
                i += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = pattern.find("]", i + 2)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = pattern[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end + 1
                continue
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)
