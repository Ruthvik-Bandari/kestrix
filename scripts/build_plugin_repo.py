# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Generate the standalone plugin repository, ``dist/claude-plugin-repo/``.

Run from the repo root: ``uv run python scripts/build_plugin_repo.py [--out DIR] [--check]``.

The output is the content of https://github.com/Ruthvik-Bandari/kestrix-claude-plugin: the ``kestrix`` Claude
Code plugin at the repository root, exactly as it ships inside the ``kestrix-scan`` wheel
(``kestrix_scan.plugin.plugin_files()``, without the ``kestrix-local`` marketplace the installer adds), plus:

- ``.claude-plugin/marketplace.json``: a one-plugin marketplace named ``kestrix`` with source ``./``;
- ``LICENSE``: the Apache-2.0 text of ``packages/kestrix-scan/LICENSE``;
- everything under ``packaging/claude-plugin-repo/``: README, PRIVACY, SECURITY, CHANGELOG, NOTICE,
  ``.gitignore``, the ``claude plugin eval`` suite in ``evals/`` and the no-network test in ``tests/``.

The build is deterministic (sorted files, fixed content, no timestamps) and refuses to write a tree that breaks
the directory's pre-submission checklist (``audit``). Writing replaces the destination's files but keeps a
``.git`` directory in it, so the owner can push from it; it replaces only an empty directory or an earlier build
(one whose ``.claude-plugin/plugin.json`` names ``kestrix``), and never follows a symbolic link. With ``--check``
it writes nothing and exits 1 when the destination differs from a fresh build.
``tests/integrations/test_claude_plugin_repo.py`` checks reproducibility and that the plugin files match the
packaged plugin byte for byte.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path, PurePosixPath

from kestrix_scan import plugin
from kestrix_scan.about import __author__, __version__
from kestrix_scan.skill import walk_files

REPO = Path(__file__).resolve().parents[1]
EXTRAS = REPO / "packaging" / "claude-plugin-repo"
LICENSE = REPO / "packages" / "kestrix-scan" / "LICENSE"
DEFAULT_OUT = REPO / "dist" / "claude-plugin-repo"
REPO_URL = "https://github.com/Ruthvik-Bandari/kestrix-claude-plugin"
MARKETPLACE_NAME = "kestrix"

# Limits and patterns from https://claude.com/docs/plugins/pre-submission-checklist (checked 2026-10-20).
MAX_TEXT_BYTES = 256 * 1024
MAX_FILES = 512
MIN_README_WORDS = 40
SYSTEM_FILES = {".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX"}
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
PACKAGE_SOURCE_CONFIGS = {".npmrc", "bunfig.toml", "uv.toml", "pip.conf", ".yarnrc", ".yarnrc.yml", ".pypirc"}
LOCKFILE_INSTALLS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "bun.lock", "bun.lockb"}
LAUNCHER = re.compile(
    r"\b(?:npx|bunx|uvx|pnpm\s+dlx|yarn\s+dlx|pipx\s+run|uv\s+run|pip3?\s+install|npm\s+(?:install|i|ci)|uv\s+pip\s+install)\b"
)
HOOK_COMMAND = re.compile(r'python3 "\$\{CLAUDE_PLUGIN_ROOT\}/([A-Za-z0-9_./-]+)" [a-z-]+')
FOLDER_NAME = re.compile(r"[A-Za-z0-9._-]+")


def marketplace() -> bytes:
    """The self-hosted marketplace: ``/plugin marketplace add Ruthvik-Bandari/kestrix-claude-plugin``."""
    manifest = json.loads(dict(plugin_tree())[plugin.MANIFEST])
    entry = {
        "name": plugin.PLUGIN_NAME,
        "source": "./",
        "description": "Scans every file Claude writes with the local kestrix-scan scanner and has Claude fix the findings, plus secure-review skills and /kestrix:scan, /kestrix:fix and /kestrix:review. Offline; hooks open no network connections.",
        "version": __version__,
        "author": {"name": __author__},
        "homepage": REPO_URL,
        "repository": REPO_URL,
        "license": manifest["license"],
        "category": "security",
        "tags": ["security", "sast", "secrets", "code-review"],
    }
    data = {
        "name": MARKETPLACE_NAME,
        "owner": {"name": __author__, "url": "https://github.com/Ruthvik-Bandari"},
        "description": "The Kestrix Claude Code plugin: local, deterministic security checks on the code Claude writes.",
        "plugins": [entry],
    }
    return (json.dumps(data, indent=2) + "\n").encode()


def plugin_tree() -> list[tuple[PurePosixPath, bytes]]:
    """The packaged plugin's own files, without the installer's ``kestrix-local`` marketplace."""
    return [(path, data) for path, data in plugin.plugin_files() if path != plugin.MARKETPLACE]


def render() -> list[tuple[PurePosixPath, bytes]]:
    """Every file of the plugin repository as (relative path, bytes), sorted by path."""
    files = dict(plugin_tree())
    extras = list(walk_files(EXTRAS, PurePosixPath(), keep=frozenset({".gitignore"})))
    extras += [(PurePosixPath("LICENSE"), LICENSE.read_bytes()), (plugin.MARKETPLACE, marketplace())]
    for path, data in extras:
        if path in files:
            raise SystemExit(f"{path} is both a plugin file and a repository file")
        files[path] = data
    tree = sorted(files.items(), key=lambda item: str(item[0]))
    problems = audit(tree)
    if problems:
        raise SystemExit("the plugin repository breaks the pre-submission checklist:\n- " + "\n- ".join(problems))
    return tree


def _readme_words(text: str) -> int:
    return len(re.sub(r"```.*?```", " ", text, flags=re.S).split())


def _name_problems(paths: list[PurePosixPath]) -> list[str]:
    problems: list[str] = []
    seen: dict[str, PurePosixPath] = {}
    for path in paths:
        for i, part in enumerate(path.parts):
            if part in SYSTEM_FILES:
                problems.append(f"{path}: system file {part}")
            if ":" in part or part.endswith((".", " ")) or part.split(".")[0].lower() in WINDOWS_DEVICES:
                problems.append(f"{path}: {part!r} is not a valid Windows file name")
            if i < len(path.parts) - 1 and not FOLDER_NAME.fullmatch(part):
                problems.append(f"{path}: folder {part!r} must use letters, digits, dots, hyphens and underscores")
        key = str(path).lower()
        if key in seen:
            problems.append(f"{path} and {seen[key]} differ only by capitalization")
        seen[key] = path
    return problems


def _hook_problems(files: dict[PurePosixPath, bytes]) -> list[str]:
    problems: list[str] = []
    config = json.loads(files[PurePosixPath("hooks/hooks.json")])
    if set(config) != {"hooks"}:
        problems.append("hooks/hooks.json must hold only a top-level 'hooks' object")
    scripts: set[PurePosixPath] = set()
    for groups in config["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                match = HOOK_COMMAND.fullmatch(hook.get("command", ""))
                if hook.get("type") != "command" or match is None:
                    problems.append(f"hook command {hook.get('command')!r} is not python3 on a file in the plugin")
                    continue
                script = PurePosixPath(match.group(1))
                if ".." in script.parts or script not in files:
                    problems.append(f"hook script {script} is not a file inside the plugin")
                scripts.add(script)
    for script in sorted(scripts, key=str):
        if script in files and LAUNCHER.search(files[script].decode("utf-8")):
            problems.append(f"{script} mentions a package launcher or install")
    return problems


def audit(tree: list[tuple[PurePosixPath, bytes]]) -> list[str]:
    """Checklist problems in ``tree``; an empty list means it passes every check made here."""
    files = dict(tree)
    problems = _name_problems(list(files))
    if len(files) > MAX_FILES:
        problems.append(f"{len(files)} files; the directory holds a plugin with more than {MAX_FILES} for review")
    for path, data in files.items():
        if len(data) >= MAX_TEXT_BYTES:
            problems.append(f"{path} is {len(data)} bytes; text files must stay under {MAX_TEXT_BYTES}")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{path} is not UTF-8 text; the plugin ships no binaries")
        if path.name in PACKAGE_SOURCE_CONFIGS:
            problems.append(f"{path} configures a package source")
        if len(path.parts) == 1 and path.name in LOCKFILE_INSTALLS:
            problems.append(f"{path} makes Claude Code install packages at plugin install")
    manifest = json.loads(files[plugin.MANIFEST])
    if any(key not in manifest for key in ("name", "version", "description", "author", "license")):
        problems.append("plugin.json needs name, version, description, author and license")
    if "userConfig" in manifest:
        problems.append("plugin.json declares userConfig; this plugin takes no credentials or options")
    readme = files.get(PurePosixPath("README.md"))
    if readme is None or _readme_words(readme.decode("utf-8")) < MIN_README_WORDS:
        problems.append(f"README.md must have at least {MIN_README_WORDS} words outside code blocks")
    if PurePosixPath("LICENSE") not in files:
        problems.append("LICENSE is missing")
    return problems + _hook_problems(files)


def read_tree(root: Path) -> list[tuple[PurePosixPath, bytes]]:
    """The files under ``root`` as (relative path, bytes), sorted, leaving out ``.git``."""
    found = [
        (PurePosixPath(path.relative_to(root).as_posix()), path.read_bytes())
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(root).parts
    ]
    return sorted(found, key=lambda item: str(item[0]))


def _replaceable(dest: Path) -> bool:
    manifest = dest / ".claude-plugin" / "plugin.json"
    if not any(child.name != ".git" for child in dest.iterdir()):
        return True
    if manifest.is_symlink() or not manifest.is_file():
        return False
    try:
        return json.loads(manifest.read_text(encoding="utf-8")).get("name") == plugin.PLUGIN_NAME
    except ValueError:
        return False


def write(dest: Path, tree: list[tuple[PurePosixPath, bytes]]) -> None:
    """Replace the files of ``dest`` with ``tree``, keeping ``dest/.git``."""
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise SystemExit(f"{dest} is a symbolic link or a file; refusing to replace it")
    dest.mkdir(parents=True, exist_ok=True)
    if not _replaceable(dest):
        raise SystemExit(f"{dest} holds something other than an earlier build of the plugin repository; refusing")
    for child in dest.iterdir():
        if child.name == ".git":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for path, data in tree:
        target = dest.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="destination (default dist/claude-plugin-repo)")
    parser.add_argument("--check", action="store_true", help="exit 1 when --out differs from a fresh build")
    args = parser.parse_args(argv)
    tree = render()
    if args.check:
        if not args.out.is_dir() or read_tree(args.out) != tree:
            print(f"{args.out} is out of date; run scripts/build_plugin_repo.py", file=sys.stderr)
            return 1
        return 0
    write(args.out, tree)
    print(f"wrote {len(tree)} files to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
