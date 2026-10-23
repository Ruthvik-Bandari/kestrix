# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Read pinned dependencies from lockfiles with the standard library only.

This module reads the Python and npm files; ``lockfiles_more`` reads Packagist, Go, crates.io, Maven, RubyGems,
NuGet, Pub and Bun files, and its parsers are registered in ``PARSERS`` below.

Supported files (matched by name):

- ``requirements*.txt`` and ``*.txt`` under a ``requirements/`` directory: only exact pins
  (``name==1.2.3``, ``name===1.2.3``) are checked; other requirement lines are listed as not checked.
  Options (``-r``, ``-e``, ``--hash``) and URL or path requirements are skipped.
- ``poetry.lock``, ``uv.lock`` and ``pdm.lock`` (TOML ``[[package]]`` tables). Packages from git, a
  path, a URL or the workspace itself are skipped, because their version is not a registry release.
- ``Pipfile.lock`` (JSON ``default`` and ``develop``).
- ``package-lock.json`` and ``npm-shrinkwrap.json`` version 2 or 3 (the ``packages`` map). Linked
  packages and the root project are skipped; a version 1 file is reported as unsupported.
- ``yarn.lock`` version 1 and Berry (version 2 and later), read line by line; Berry entries are
  checked only for the ``npm:`` protocol.
- ``pnpm-lock.yaml`` versions 5 to 9: only the package keys under the top-level ``packages:`` (or
  ``snapshots:``) mapping are read, line by line. This is not a YAML parser; anything else is ignored.

Each dependency keeps the 1-based line it was found on, so findings point into the lockfile.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10: the tomli backport
    import tomli as tomllib

MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
# The OSV ecosystems kestrix-scan can check (the names OSV uses in its exports and advisories).
ECOSYSTEMS = ("PyPI", "npm", "Packagist", "Go", "crates.io", "Maven", "RubyGems", "NuGet", "Pub")


@dataclass(frozen=True, slots=True)
class Dependency:
    ecosystem: (
        str  # OSV ecosystem name: 'PyPI', 'npm', 'Packagist', 'Go', 'crates.io', 'Maven', 'RubyGems', 'NuGet' or 'Pub'
    )
    name: str  # as written in the file
    version: str
    line: int  # 1-based line in the lockfile


@dataclass
class Parsed:
    dependencies: list[Dependency] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)  # requirement lines without an exact pin
    unsupported: str | None = None  # why the file could not be read, if it could not


def normalize(ecosystem: str, name: str) -> str:
    """The name OSV and the index use: PEP 503 normalization for PyPI, lower case for Packagist and NuGet
    (their names are case-insensitive), unchanged elsewhere."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if ecosystem in ("Packagist", "NuGet") else name


def _line_finder(text: str) -> Callable[[str], int]:
    """A function returning the 1-based line of a needle, searching from the last match on; 0 when it is absent."""
    starts = [0]
    starts.extend(i + 1 for i, char in enumerate(text) if char == "\n")
    position = 0

    def find(needle: str) -> int:
        nonlocal position
        index = text.find(needle, position)
        if index < 0:
            index = text.find(needle)
        if index < 0:
            return 0
        position = index + len(needle)
        low, high = 0, len(starts)
        while low + 1 < high:
            middle = (low + high) // 2
            if starts[middle] <= index:
                low = middle
            else:
                high = middle
        return low + 1

    return find


# ----- requirements.txt

_REQ_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_PIN = re.compile(rf"\s*(?P<name>{_REQ_NAME})\s*(?:\[[^\]]*\])?\s*===?\s*(?P<version>[A-Za-z0-9!+._-]+)\s*(?:;.*)?")
_REQUIREMENT = re.compile(rf"\s*(?P<name>{_REQ_NAME})\s*(?:\[[^\]]*\])?\s*(?P<rest>.*)")


def parse_requirements(text: str) -> Parsed:
    parsed = Parsed()
    lines = text.splitlines()
    number = 0
    while number < len(lines):
        start = number + 1
        line = lines[number]
        while line.rstrip().endswith("\\") and number + 1 < len(lines):
            number += 1
            line = line.rstrip()[:-1] + " " + lines[number]
        number += 1
        body = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]
        body = re.split(r"\s--?[a-z]", " " + body, maxsplit=1)[0].strip()  # drop trailing options such as --hash
        if not body or body.startswith("-") or "://" in body or "@" in body or body.startswith((".", "/")):
            continue
        pin = _PIN.fullmatch(body)
        if pin is not None and "*" not in pin.group("version"):
            parsed.dependencies.append(Dependency("PyPI", pin.group("name"), pin.group("version"), start))
        elif _REQUIREMENT.fullmatch(body):
            parsed.not_checked.append(body)
    return parsed


# ----- TOML lockfiles: poetry.lock, uv.lock, pdm.lock

_NON_REGISTRY_SOURCES = frozenset({"git", "path", "directory", "file", "url", "editable", "virtual"})


def _registry_package(package: dict[str, Any]) -> bool:
    source = package.get("source")
    if isinstance(source, dict):  # poetry: {type = "git", url = ...}; uv: {git = ...} or {registry = ...}
        kinds = {str(source["type"]).lower()} if "type" in source else set(map(str, source))
        return not (kinds & _NON_REGISTRY_SOURCES)
    return not any(key in package for key in ("path", "git", "url", "editable"))


def parse_toml_lock(text: str) -> Parsed:
    return _toml_packages(text, "PyPI", _registry_package)


def _toml_packages(text: str, ecosystem: str, is_registry: Callable[[dict[str, Any]], bool]) -> Parsed:
    """The ``[[package]]`` tables of a TOML lockfile that ``is_registry`` accepts, with their lockfile lines."""
    parsed = Parsed()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        parsed.unsupported = f"not valid TOML ({exc})"
        return parsed
    packages = data.get("package")
    if not isinstance(packages, list):
        return parsed
    find = _line_finder(text)
    for package in packages:
        if not isinstance(package, dict):
            continue
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        header = find(f'[[package]]\nname = "{name}"')
        line = header + 1 if header else max(find(f'name = "{name}"'), 1)
        if is_registry(package):
            parsed.dependencies.append(Dependency(ecosystem, name, version, line))
    return parsed


# ----- JSON lockfiles: Pipfile.lock, package-lock.json


def _load_json(text: str, parsed: Parsed) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        parsed.unsupported = "not valid JSON"
        return None


def parse_pipfile_lock(text: str) -> Parsed:
    parsed = Parsed()
    data = _load_json(text, parsed)
    if not isinstance(data, dict):
        return parsed
    find = _line_finder(text)
    for section in ("default", "develop"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            version = entry.get("version") if isinstance(entry, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                parsed.dependencies.append(
                    Dependency("PyPI", name, version.lstrip("="), max(find(json.dumps(name) + ":"), 1))
                )
    return parsed


def parse_package_lock(text: str) -> Parsed:
    parsed = Parsed()
    data = _load_json(text, parsed)
    if not isinstance(data, dict):
        return parsed
    packages = data.get("packages")
    if not isinstance(packages, dict):
        parsed.unsupported = "lockfileVersion 1 is not supported; run npm install with npm 7 or newer to upgrade it"
        return parsed
    find = _line_finder(text)
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict) or entry.get("link") is True:
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else key.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if "node_modules/" not in key or not isinstance(version, str) or not isinstance(name, str):
            continue
        parsed.dependencies.append(Dependency("npm", name, version, max(find(json.dumps(key) + ":"), 1)))
    return parsed


# ----- yarn.lock


def _spec_name(spec: str) -> str:
    """``@scope/name@^1`` -> ``@scope/name``; ``name@npm:^1`` -> ``name``."""
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def parse_yarn_lock(text: str) -> Parsed:
    parsed = Parsed()
    berry = "__metadata:" in text
    header: tuple[str, int] | None = None
    resolution: str | None = None

    def flush(version: str | None) -> None:
        if header is None or version is None:
            return
        name, line = header
        if berry and (resolution is None or "@npm:" not in resolution):
            return
        parsed.dependencies.append(Dependency("npm", name, version, line))

    version: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            flush(version)
            header, version, resolution = None, None, None
            if raw.rstrip().endswith(":") and not raw.startswith("__metadata"):
                first = raw.rstrip()[:-1].split(",")[0]
                header = (_spec_name(first), number)
            continue
        stripped = raw.strip()
        match = re.fullmatch(r'version:?\s+"?([^"\s]+)"?', stripped)
        if match is not None and raw.startswith("  ") and not raw.startswith("   "):
            version = match.group(1)
        elif stripped.startswith("resolution:"):
            resolution = stripped.split(":", 1)[1].strip().strip('"')
    flush(version)
    return parsed


# ----- pnpm-lock.yaml (package keys only)

_PNPM_KEY = re.compile(r"""^ {2}['"]?/?(?P<key>[^'"\s][^'"]*?)['"]?:\s*(?:\{\})?\s*$""")


_PNPM_V5 = re.compile(r"(?P<name>(?:@[^/@]+/)?[^/@]+)/(?P<version>[0-9][^_/]*)(?:_.*)?")


def _pnpm_name_version(key: str) -> tuple[str, str] | None:
    """``name@1.2.3(peer@1)`` (v6 and later) or ``name/1.2.3_peer@1`` (v5) -> (name, version)."""
    v5 = _PNPM_V5.fullmatch(key)
    if v5 is not None:
        return v5.group("name"), v5.group("version")
    key = key.split("(", 1)[0]
    at = key.rfind("@")
    name, version = (key[:at], key[at + 1 :]) if at > 0 else ("", "")
    return (name, version) if name and version[:1].isdigit() else None


def parse_pnpm_lock(text: str) -> Parsed:
    parsed = Parsed()
    section: str | None = None
    seen: set[tuple[str, str]] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            section = raw.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        match = _PNPM_KEY.match(raw)
        if match is None:
            continue
        found = _pnpm_name_version(match.group("key"))
        if found is not None and found not in seen:
            seen.add(found)
            parsed.dependencies.append(Dependency("npm", found[0], found[1], number))
    return parsed


# ----- dispatch

from .lockfiles_more import MORE_PARSERS  # noqa: E402 - the parsers import Dependency and Parsed from this module

PARSERS: dict[str, Callable[[str], Parsed]] = {
    "poetry.lock": parse_toml_lock,
    "uv.lock": parse_toml_lock,
    "pdm.lock": parse_toml_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
}
_REQUIREMENTS = re.compile(r"requirements.*\.txt", re.IGNORECASE)
PARSERS.update(MORE_PARSERS)

# The OSV ecosystem a dependency file belongs to, by name: which exports `db update` needs for a project.
FILE_ECOSYSTEMS: dict[str, str] = {
    "poetry.lock": "PyPI",
    "uv.lock": "PyPI",
    "pdm.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "composer.lock": "Packagist",
    "go.mod": "Go",
    "go.sum": "Go",
    "Cargo.lock": "crates.io",
    "pom.xml": "Maven",
    "gradle.lockfile": "Maven",
    "Gemfile.lock": "RubyGems",
    "packages.lock.json": "NuGet",
    "pubspec.lock": "Pub",
}


def ecosystem_for_file(rel: str) -> str | None:
    """The OSV ecosystem of a dependency file path, or None when it is not one (or, for bun.lockb, unreadable)."""
    path = PurePosixPath(rel)
    if path.name in FILE_ECOSYSTEMS:
        return FILE_ECOSYSTEMS[path.name]
    if parser_for(rel) is parse_requirements:
        return "PyPI"
    return None


def parser_for(rel: str) -> Callable[[str], Parsed] | None:
    """The parser for a file path relative to the scan root, or None when it is not a dependency file."""
    path = PurePosixPath(rel)
    if path.name in PARSERS:
        return PARSERS[path.name]
    if _REQUIREMENTS.fullmatch(path.name) or (path.suffix == ".txt" and path.parent.name == "requirements"):
        return parse_requirements
    return None
