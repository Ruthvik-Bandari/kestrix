# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix-scan init``: set a project up for the scanner without rewriting files it does not own.

- ``pyproject.toml``: a minimal ``[tool.kestrix]`` table is appended as text. The rest of the file
  is never rewritten. An existing table is left alone unless ``force``, which replaces only a plain
  ``[tool.kestrix]`` section. Without a ``pyproject.toml``, ``.kestrix.toml`` is written instead.
- ``.pre-commit-config.yaml``: written when missing or empty. A file with other content is never
  edited; the entry to add is printed instead.
- ``.github/workflows/kestrix.yml`` (``ci="github"``): a workflow that runs the scanner and uploads
  SARIF to GitHub code scanning, with SHA-pinned actions and minimal permissions. An existing,
  different file is replaced only with ``force``.
- The Claude Code plugin (``claude_plugin``): installed to ``~/.claude/kestrix-plugin``.

Every step is idempotent: running ``init`` again reports what is already in place.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from . import plugin
from .about import __version__

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10: the tomli backport
    import tomli as tomllib

REPO_URL = "https://github.com/Ruthvik-Bandari/kestrix"
DOCS_URL = f"{REPO_URL}/blob/main/packages/kestrix-scan/README.md"
WORKFLOW = Path(".github/workflows/kestrix.yml")
PRE_COMMIT = Path(".pre-commit-config.yaml")
MAX_EDIT_BYTES = 1024 * 1024

TOOL_TABLE = f"""[tool.kestrix]
# kestrix-scan settings, see {DOCS_URL}#configuration
fail-on = "high"
exclude = []
"""
OWN_FILE = TOOL_TABLE.replace("[tool.kestrix]\n", "")

PRE_COMMIT_ENTRY = f"""  - repo: {REPO_URL}
    rev: v{__version__}
    hooks:
      - id: kestrix-scan
"""

# Actions are pinned to full commit SHAs (resolved with `gh api repos/<owner>/<repo>/commits/<tag>`);
# the tag each SHA was resolved from is in the comment beside it.
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"
UPLOAD_SARIF = "github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0"

WORKFLOW_TEXT = f"""# Written by kestrix-scan init: scans the repository and uploads the findings to GitHub code scanning.
# The scan step never fails the job; findings appear under Security > Code scanning.
name: Kestrix

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  kestrix-scan:
    name: kestrix-scan
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - uses: {SETUP_PYTHON}
        with:
          python-version: "3.13"
      - run: pip install kestrix-scan=={__version__}
      - run: kestrix-scan --format sarif --output kestrix.sarif || true
      - uses: {UPLOAD_SARIF}
        with:
          sarif_file: kestrix.sarif
          category: kestrix
"""


class InitError(Exception):
    """Raised when a step is refused, for example a broken pyproject.toml."""


def _write(path: Path, text: str) -> None:
    """Atomically write ``text`` to ``path`` (mode 0644), creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read(path: Path) -> str:
    if path.is_symlink():
        raise InitError(f"{path} is a symbolic link; refusing to follow it")
    try:
        if path.stat().st_size > MAX_EDIT_BYTES:
            raise InitError(f"{path} is larger than {MAX_EDIT_BYTES:,} bytes")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InitError(f"cannot read {path}: {exc}") from None


_TABLE_HEADER = re.compile(r"^\s*\[\s*tool\s*\.\s*kestrix\s*\]\s*(?:#.*)?$")
_ANY_HEADER = re.compile(r"^\s*\[")


def _replace_table(text: str) -> str | None:
    """``text`` without its ``[tool.kestrix]`` section, or None when the table is written another way."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if _TABLE_HEADER.match(line)]
    if len(starts) != 1:
        return None
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if _ANY_HEADER.match(lines[i])), len(lines))
    if any(re.match(r"^\s*\[\s*tool\s*\.\s*kestrix\s*\.", line) for line in lines[end:]):
        return None
    return "".join(lines[:start] + lines[end:])


def _append(text: str, block: str) -> str:
    if not text:
        return block
    return text + ("\n" if text.endswith("\n") else "\n\n") + block


def configure(root: Path, *, force: bool) -> str:
    """Add ``[tool.kestrix]`` to ``pyproject.toml`` (or write ``.kestrix.toml``); returns what was done."""
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        own = root / ".kestrix.toml"
        if own.exists() and not force:
            return f"{own}: already present; left unchanged (pass --force to replace it)"
        _write(own, OWN_FILE)
        return f"{own}: wrote the default settings (no pyproject.toml found)"
    text = _read(pyproject)
    try:
        tool = tomllib.loads(text).get("tool")
    except tomllib.TOMLDecodeError as exc:
        raise InitError(f"{pyproject} is not valid TOML ({exc}); fix it first") from None
    if isinstance(tool, dict) and "kestrix" in tool:
        if not force:
            return f"{pyproject}: [tool.kestrix] already present; left unchanged (pass --force to replace it)"
        stripped = _replace_table(text)
        if stripped is None:
            raise InitError(f"{pyproject}: [tool.kestrix] is not a plain table section; edit it by hand")
        _write(pyproject, _append(stripped.rstrip("\n") + "\n" if stripped.strip() else "", TOOL_TABLE))
        return f"{pyproject}: replaced [tool.kestrix] with the defaults"
    _write(pyproject, _append(text, TOOL_TABLE))
    return f"{pyproject}: appended [tool.kestrix]"


def write_pre_commit(root: Path) -> str:
    """Write ``.pre-commit-config.yaml`` when missing or empty; otherwise say what to add."""
    path = root / PRE_COMMIT
    if path.exists():
        text = _read(path)
        if "id: kestrix-scan" in text:
            return f"{path}: the kestrix-scan hook is already configured"
        if text.strip():
            return f"{path}: has other content, so it was not changed. Add this under `repos:`:\n{PRE_COMMIT_ENTRY.rstrip()}"
    _write(path, "repos:\n" + PRE_COMMIT_ENTRY)
    return f"{path}: wrote the kestrix-scan hook (run `pre-commit install` to enable it)"


def github_workflow(root: Path, *, force: bool) -> str:
    path = root / WORKFLOW
    if path.exists():
        if _read(path) == WORKFLOW_TEXT:
            return f"{path}: already up to date"
        if not force:
            return f"{path}: exists with other content; left unchanged (pass --force to replace it)"
    _write(path, WORKFLOW_TEXT)
    return f"{path}: wrote a workflow that uploads kestrix.sarif to GitHub code scanning"


def install_plugin(*, force: bool) -> str:
    dest = plugin.default_dest()
    if dest.exists() and not force and plugin._holds_this_plugin(dest):
        return f"{dest}: the Claude Code plugin is already installed (pass --force to update it)"
    path = plugin.install(dest, force=force)
    return f"{path}: installed the Claude Code plugin. Enable it with: claude plugin marketplace add {path}"


def init(
    root: Path, *, ci: str | None = None, pre_commit: bool = False, claude_plugin: bool = False, force: bool = False
) -> list[str]:
    """Run the requested steps in ``root`` and return one line per step."""
    if not root.is_dir():
        raise InitError(f"{root} is not a directory")
    steps = [configure(root, force=force)]
    if pre_commit:
        steps.append(write_pre_commit(root))
    if ci == "github":
        steps.append(github_workflow(root, force=force))
    if claude_plugin:
        steps.append(install_plugin(force=force))
    return steps
