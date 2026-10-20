# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Install and package the bundled ``kestrix`` Claude Code plugin.

The plugin is package data under ``claude_plugin/kestrix/``: a manifest, hooks, a stdlib hook
script and skills. Installing copies it into a directory that is also a one-plugin local
marketplace (``.claude-plugin/marketplace.json`` with source ``./``), so Claude Code can load it
with ``--plugin-dir`` for one session or add it with ``claude plugin marketplace add``. Nothing is
written to Claude Code's settings. The same symlink and overwrite safety as the skill installer
applies (``skill.install_tree``).
"""

from __future__ import annotations

import json
import os
import sys
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from .about import __author__, __version__
from .skill import SkillError, install_tree, walk_files, write_zip

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:  # Python 3.10 has it only in importlib.abc
        from importlib.abc import Traversable

PLUGIN_NAME = "kestrix"
LOCAL_MARKETPLACE = "kestrix-local"
MANIFEST = PurePosixPath(".claude-plugin/plugin.json")
MARKETPLACE = PurePosixPath(".claude-plugin/marketplace.json")


class PluginError(SkillError):
    """Raised when a plugin install or package request is refused."""


def default_dest() -> Path:
    return Path.home() / ".claude" / "kestrix-plugin"


def plugin_source() -> Traversable:
    return files("kestrix_scan") / "claude_plugin" / PLUGIN_NAME


def local_marketplace() -> bytes:
    """The ``marketplace.json`` that makes an installed copy a local marketplace of one plugin."""
    manifest = {
        "name": LOCAL_MARKETPLACE,
        "owner": {"name": __author__},
        "description": "Local copy of the Kestrix Claude Code plugin, written by kestrix-scan install-claude-plugin.",
        "plugins": [
            {
                "name": PLUGIN_NAME,
                "source": "./",
                "description": "Kestrix security hooks, skills and commands.",
                "version": __version__,
            }
        ],
    }
    return (json.dumps(manifest, indent=2) + "\n").encode()


def plugin_files() -> list[tuple[PurePosixPath, bytes]]:
    """Every file of the packaged plugin plus the local marketplace, as (relative path, bytes), sorted."""
    found = list(walk_files(plugin_source(), PurePosixPath(), keep=frozenset({".claude-plugin"})))
    if not any(path == MANIFEST for path, _ in found):
        raise PluginError("the packaged plugin is missing .claude-plugin/plugin.json; reinstall kestrix-scan")
    found.append((MARKETPLACE, local_marketplace()))
    return sorted(found, key=lambda item: str(item[0]))


def _holds_this_plugin(path: Path) -> bool:
    manifest = path.joinpath(*MANIFEST.parts)
    if manifest.is_symlink() or not manifest.is_file() or path.joinpath(".claude-plugin").is_symlink():
        return False
    try:
        data = json.loads(manifest.read_text(encoding="utf-8", errors="replace")[:65536])
    except ValueError:
        return False
    return isinstance(data, dict) and data.get("name") == PLUGIN_NAME


def install(dest: Path | None = None, *, force: bool = False) -> Path:
    """Copy the plugin to ``dest`` (default ``~/.claude/kestrix-plugin``) and return its path."""
    target = Path(os.path.abspath(dest if dest is not None else default_dest()))
    return install_tree(target, plugin_files(), holds=_holds_this_plugin, what=f"the {PLUGIN_NAME} plugin", force=force)


def package(out: Path, *, force: bool = False) -> Path:
    """Write a deterministic zip with the plugin at its top level, for ``claude --plugin-dir FILE.zip``."""
    target = Path(os.path.abspath(out))
    if target.is_symlink():
        raise PluginError(f"{target} is a symbolic link; refusing to follow it")
    if target.exists() and (target.is_dir() or not force):
        raise PluginError(f"{target} already exists; pass --force to replace it")
    return write_zip(target, None, plugin_files())
