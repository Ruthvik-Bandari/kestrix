# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Project configuration: ``[tool.kestrix]`` in ``pyproject.toml``, or a ``.kestrix.toml`` file.

Discovery starts at the scan root and walks up. In each directory ``.kestrix.toml`` is read first
(its keys sit at the top level), then ``pyproject.toml`` when it has a ``[tool.kestrix]`` table.
The first one found wins; the walk stops at the directory holding ``.git`` or at the filesystem root.

Keys::

    [tool.kestrix]
    fail-on = "high"                      # low, medium, high, critical or none
    exclude = ["tests/fixtures/**", "*.min.js"]
    baseline = ".kestrix-baseline.json"   # relative to the file's directory
    rules.enable = ["py.", "secret."]     # rule ids or prefixes; default: every rule
    rules.disable = ["py.crypto.weak_hash"]
    ignore-advisories = {"GHSA-xxxx-xxxx-xxxx" = "not reachable: we never parse untrusted XML"}
    claude.install-guard = false          # turn off the Claude Code install guard for this project

Unknown keys produce a warning. Unknown rule ids, bad values and unreadable files raise ``Rejected``.
"""

from __future__ import annotations

import difflib
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import Reason, Rejected
from .models import FailOnLevel
from .registry import RULES
from .walk import _glob_regex

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10: the tomli backport, the only dependency kestrix-scan has
    import tomli as tomllib

FAIL_ON_CHOICES: tuple[str, ...] = ("low", "medium", "high", "critical", "none")
CONFIG_FILE = ".kestrix.toml"
PYPROJECT = "pyproject.toml"
MAX_CONFIG_BYTES = 1024 * 1024
_TOP_KEYS = frozenset({"fail-on", "exclude", "baseline", "rules", "ignore-advisories", "claude"})
_RULE_KEYS = frozenset({"enable", "disable"})
_CLAUDE_KEYS = frozenset({"install-guard"})


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """Scanner settings. Every field is optional; ``None`` means the built-in default."""

    fail_on: FailOnLevel | None = None
    exclude: tuple[str, ...] = ()
    enable: tuple[str, ...] = ()  # rule ids or prefixes; empty means every rule
    disable: tuple[str, ...] = ()
    baseline: Path | None = None
    ignore_advisories: tuple[tuple[str, str], ...] = ()  # (advisory id or alias, reason)
    install_guard: bool | None = None  # claude.install-guard; None means on
    source: Path | None = None  # the file the settings came from, if any
    warnings: tuple[str, ...] = field(default=(), compare=False)

    def active_rules(self) -> frozenset[str]:
        """The rule ids left after ``enable`` and ``disable``."""
        enabled = [rule for rule in RULES if not self.enable or any(_selects(item, rule) for item in self.enable)]
        return frozenset(rule for rule in enabled if not any(_selects(item, rule) for item in self.disable))

    def excluded(self, rel: str) -> bool:
        """True when ``exclude`` matches the posix path ``rel`` (relative to the scan root) or a parent directory.

        As in ``.gitignore``, a glob with a ``/`` is matched against the path from the root, and a glob
        without one against each file or directory name; ``*`` stays within a name and ``**`` crosses them.
        """
        if not self.exclude:
            return False
        parts = rel.split("/")
        prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
        for regex, anchored in _exclude_patterns(self.exclude):
            if any(regex.fullmatch(text) for text in (prefixes if anchored else parts)):
                return True
        return False


def _selects(item: str, rule_id: str) -> bool:
    prefix = item if item.endswith(".") else item + "."
    return rule_id == item or rule_id.startswith(prefix)


def _known_selectors() -> list[str]:
    prefixes = {".".join(rule.split(".")[:depth]) + "." for rule in RULES for depth in range(1, rule.count(".") + 1)}
    return sorted({*RULES, *prefixes})


def check_rule_selectors(items: Iterable[str], key: str) -> tuple[str, ...]:
    """The items, unchanged, or ``Rejected`` naming the first one that selects no rule, with a suggestion."""
    found = tuple(items)
    for item in found:
        if any(_selects(item, rule) for rule in RULES):
            continue
        close = difflib.get_close_matches(item, _known_selectors(), n=1, cutoff=0.6)
        hint = f"; did you mean {close[0]!r}?" if close else "; run `kestrix-scan rules` to list the rule ids"
        raise Rejected(Reason.INVALID_INPUT, f"{key}: unknown rule id or prefix {item!r}{hint}")
    return found


def _exclude_patterns(globs: tuple[str, ...]) -> list[tuple[re.Pattern[str], bool]]:
    found = []
    for glob in globs:
        pattern = glob.rstrip("/")
        anchored = "/" in pattern
        found.append((re.compile(_glob_regex(pattern.lstrip("/"))), anchored))
    return found


def _strings(value: Any, key: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise Rejected(Reason.INVALID_INPUT, f"{key} must be a list of non-empty strings")
    return tuple(value)


def from_mapping(data: Mapping[str, Any], *, base: Path, source: Path | None = None) -> Config:
    """A ``Config`` from the keys of a ``[tool.kestrix]`` table; ``base`` resolves a relative baseline path."""
    where = str(source) if source is not None else "configuration"
    warnings = [f"{where}: unknown key {key!r} ignored" for key in data if key not in _TOP_KEYS]
    fail_on = data.get("fail-on")
    if fail_on is not None and fail_on not in FAIL_ON_CHOICES:
        raise Rejected(Reason.INVALID_INPUT, f"{where}: fail-on must be one of {', '.join(FAIL_ON_CHOICES)}")
    baseline = data.get("baseline")
    if baseline is not None and (not isinstance(baseline, str) or not baseline):
        raise Rejected(Reason.INVALID_INPUT, f"{where}: baseline must be a path")
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise Rejected(Reason.INVALID_INPUT, f"{where}: rules must be a table with enable and disable")
    warnings += [f"{where}: unknown key 'rules.{key}' ignored" for key in rules if key not in _RULE_KEYS]
    enable = check_rule_selectors(_strings(rules.get("enable", []), "rules.enable"), f"{where}: rules.enable")
    disable = check_rule_selectors(_strings(rules.get("disable", []), "rules.disable"), f"{where}: rules.disable")
    claude = data.get("claude", {})
    if not isinstance(claude, dict):
        raise Rejected(Reason.INVALID_INPUT, f"{where}: claude must be a table")
    warnings += [f"{where}: unknown key 'claude.{key}' ignored" for key in claude if key not in _CLAUDE_KEYS]
    guard = claude.get("install-guard")
    if guard is not None and not isinstance(guard, bool):
        raise Rejected(Reason.INVALID_INPUT, f"{where}: claude.install-guard must be true or false")
    return Config(
        fail_on=fail_on,
        exclude=_strings(data.get("exclude", []), f"{where}: exclude"),
        enable=enable,
        disable=disable,
        baseline=(base / baseline) if baseline else None,
        ignore_advisories=_advisory_reasons(data.get("ignore-advisories", {}), where),
        install_guard=guard,
        source=source,
        warnings=tuple(warnings),
    )


def _advisory_reasons(value: Any, where: str) -> tuple[tuple[str, str], ...]:
    """``ignore-advisories``: a table of advisory id to a non-empty reason."""
    if not isinstance(value, dict):
        raise Rejected(Reason.INVALID_INPUT, f"{where}: ignore-advisories must be a table of advisory id = reason")
    for key, reason in value.items():
        if not isinstance(reason, str) or not any(char.isalnum() for char in reason):
            raise Rejected(Reason.INVALID_INPUT, f"{where}: ignore-advisories.{key} needs a reason")
    return tuple(sorted(value.items()))


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"{path} is larger than {MAX_CONFIG_BYTES:,} bytes")
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise Rejected(Reason.INVALID_INPUT, f"cannot read {path}: {exc.strerror}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise Rejected(Reason.INVALID_INPUT, f"{path} is not valid TOML: {exc}") from None


def load_file(path: Path) -> Config:
    """Settings from one file: ``.kestrix.toml`` (top-level keys) or ``pyproject.toml`` (``[tool.kestrix]``)."""
    data = _read_toml(path)
    if path.name == PYPROJECT:
        tool = data.get("tool", {})
        data = tool.get("kestrix", {}) if isinstance(tool, dict) else {}
        if not isinstance(data, dict):
            raise Rejected(Reason.INVALID_INPUT, f"{path}: [tool.kestrix] must be a table")
    return from_mapping(data, base=path.parent, source=path)


def find_config_file(start: Path) -> Path | None:
    """The nearest ``.kestrix.toml``, or ``pyproject.toml`` with ``[tool.kestrix]``, at or above ``start``."""
    directory = start if start.is_dir() else start.parent
    for folder in (directory, *directory.parents):
        own = folder / CONFIG_FILE
        if own.is_file():
            return own
        pyproject = folder / PYPROJECT
        if pyproject.is_file() and _has_kestrix_table(pyproject):
            return pyproject
        if (folder / ".git").exists():
            return None
    return None


def _has_kestrix_table(path: Path) -> bool:
    """True when the file has a ``[tool.kestrix]`` table. A broken file that mentions kestrix is reported, not skipped."""
    try:
        tool = _read_toml(path).get("tool")
    except Rejected:
        try:
            mentions = b"kestrix" in path.read_bytes()[:MAX_CONFIG_BYTES]
        except OSError:
            return False
        if mentions:
            raise
        return False
    return isinstance(tool, dict) and "kestrix" in tool


def discover(start: Path) -> Config:
    """Settings from the nearest configuration file at or above ``start``, or the defaults when there is none."""
    path = find_config_file(start.resolve())
    return load_file(path) if path is not None else Config()


def load_config(start: str | Path = ".") -> Config:
    """Settings from the nearest ``.kestrix.toml`` or ``pyproject.toml`` ``[tool.kestrix]`` at or above ``start``.

    Raises ``Rejected`` for an unreadable file, a bad value or an unknown rule id.
    """
    return discover(Path(start))
