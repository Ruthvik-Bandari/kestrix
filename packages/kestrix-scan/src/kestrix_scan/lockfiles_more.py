# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Lockfile parsers for Packagist, Go, crates.io, Maven, RubyGems, NuGet, Pub and Bun, standard library only.

Supported files (matched by name), each read as data (never executed, no XML parser, no YAML parser):

- ``composer.lock`` (Packagist): ``packages`` and ``packages-dev``; branch versions (``dev-main``, ``1.x-dev``) are skipped.
- ``go.mod`` (Go): ``require`` lines, with ``replace`` directives applied (a replacement by a local path is skipped).
  ``go.sum``: the highest version of each module that has a source hash line (``h1:`` without ``/go.mod``), because
  go.sum keeps superseded versions; prefer ``go.mod``, which lists the versions the build selects.
- ``Cargo.lock`` (crates.io): ``[[package]]`` tables from a registry; git, path and workspace crates are skipped.
- ``pom.xml`` (Maven): ``<dependency>`` elements whose ``<version>`` is exact or a ``<properties>`` value of the same
  file; versions from a parent POM, a BOM, ranges and unresolved ``${...}`` are listed as not checked.
  ``gradle.lockfile``: ``group:artifact:version=configurations`` lines.
- ``Gemfile.lock`` (RubyGems): the ``specs:`` of the ``GEM`` section; git and path gems are skipped, platform
  suffixes (``1.15.4-x86_64-linux``) are dropped.
- ``packages.lock.json`` (NuGet): resolved versions of non-project dependencies.
- ``pubspec.lock`` (Pub): hosted packages from pub.dev.
- ``bun.lock`` (Bun, text format); the binary ``bun.lockb`` is reported as unsupported.
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Callable
from typing import Any

from .lockfiles import Dependency, Parsed, _line_finder, _load_json, _toml_packages
from .versions import semver_key


def _starts(text: str) -> list[int]:
    return [0, *(i + 1 for i, char in enumerate(text) if char == "\n")]


def _line_at(starts: list[int], index: int) -> int:
    return bisect.bisect_right(starts, index)


# ----- composer.lock


def parse_composer_lock(text: str) -> Parsed:
    parsed = Parsed()
    data = _load_json(text, parsed)
    if not isinstance(data, dict):
        return parsed
    find = _line_finder(text)
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            name, version = entry.get("name"), entry.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            line = max(find(f'"name": "{name.replace("/", chr(92) + "/")}"'), find(f'"name": "{name}"'), 1)
            if version.startswith("dev-") or version.endswith("-dev"):
                parsed.not_checked.append(f"{name} ({version}): a branch, not a release")
                continue
            parsed.dependencies.append(Dependency("Packagist", name, version, line))
    return parsed


# ----- go.mod, go.sum

_GO_REQUIRE = re.compile(r"(?:require\s+)?(?P<mod>[^\s()]+)\s+(?P<ver>v[0-9][^\s]*)")
_GO_REPLACE = re.compile(
    r"(?:replace\s+)?(?P<old>[^\s()]+)(?:\s+(?P<oldv>v[0-9][^\s]*))?\s+=>\s+(?P<new>[^\s]+)(?:\s+(?P<newv>v[0-9][^\s]*))?"
)


def parse_go_mod(text: str) -> Parsed:
    parsed = Parsed()
    block: str | None = None
    required: list[tuple[str, str, int]] = []
    replaced: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
                continue
            statement = f"{block} {line}"
        else:
            if re.fullmatch(r"(require|replace|exclude|retract)\s*\(", line):
                block = line.split("(")[0].strip()
                continue
            statement = line
        if statement.startswith("require "):
            match = _GO_REQUIRE.fullmatch(statement)
            if match is not None:
                required.append((match.group("mod"), match.group("ver"), number))
        elif statement.startswith("replace "):
            match = _GO_REPLACE.fullmatch(statement)
            if match is not None:
                replaced[(match.group("old"), match.group("oldv"))] = (match.group("new"), match.group("newv"))
    for module, version, number in required:
        target = replaced.get((module, version)) or replaced.get((module, None))
        if target is None:
            parsed.dependencies.append(Dependency("Go", module, version, number))
        elif target[1] is not None:  # a local path (or a module without a version) is not a registry release
            parsed.dependencies.append(Dependency("Go", target[0], target[1], number))
    return parsed


def parse_go_sum(text: str) -> Parsed:
    parsed = Parsed()
    best: dict[str, tuple[Any, str, int]] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        parts = raw.split()
        if len(parts) != 3 or not parts[2].startswith("h1:") or parts[1].endswith("/go.mod"):
            continue
        module, version = parts[0], parts[1]
        key = semver_key(version)
        current = best.get(module)
        if current is None or (key is not None and (current[0] is None or key > current[0])):
            best[module] = (key, version, number)
    parsed.dependencies = [Dependency("Go", module, version, number) for module, (_, version, number) in best.items()]
    return parsed


# ----- Cargo.lock


def parse_cargo_lock(text: str) -> Parsed:
    return _toml_packages(
        text, "crates.io", lambda package: str(package.get("source", "")).startswith(("registry+", "sparse+"))
    )


# ----- pom.xml, gradle.lockfile

_XML_COMMENT = re.compile(r"<!--.*?-->|<!\[CDATA\[.*?\]\]>", re.DOTALL)
_DEPENDENCY = re.compile(r"<dependency\b[^>]*>(?P<body>.*?)</dependency\s*>", re.DOTALL)
_EXCLUSIONS = re.compile(r"<exclusions\b.*?</exclusions\s*>", re.DOTALL)
_PROPERTIES = re.compile(r"<properties\b[^>]*>(?P<body>.*?)</properties\s*>", re.DOTALL)
_PROPERTY = re.compile(r"<(?P<key>[A-Za-z0-9_.-]+)>\s*(?P<value>[^<]*?)\s*</(?P=key)>")
_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")
_MAVEN_EXACT = re.compile(r"\[?(?P<v>[0-9][0-9A-Za-z_.+-]*)\]?")


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group())


def _tag(body: str, name: str) -> str | None:
    match = re.search(rf"<{name}>\s*([^<]*?)\s*</{name}>", body)
    return match.group(1) if match is not None else None


def parse_pom(text: str) -> Parsed:
    parsed = Parsed()
    text = _XML_COMMENT.sub(_blank, text)
    starts = _starts(text)
    properties = {
        m.group("key"): m.group("value")
        for block in _PROPERTIES.finditer(text)
        for m in _PROPERTY.finditer(block.group("body"))
    }
    for match in _DEPENDENCY.finditer(text):
        body = _EXCLUSIONS.sub("", match.group("body"))
        group, artifact, version = _tag(body, "groupId"), _tag(body, "artifactId"), _tag(body, "version")
        if not group or not artifact or "${" in group + artifact:
            continue
        line = _line_at(starts, match.start())
        name = f"{group}:{artifact}"
        for _ in range(5):  # nested placeholders, bounded
            if version is None or "${" not in version:
                break
            version = _PLACEHOLDER.sub(lambda m: properties.get(m.group(1), m.group(0)), version)
        if version is None:
            parsed.not_checked.append(f"{name} (version managed by a parent POM or BOM)")
            continue
        exact = _MAVEN_EXACT.fullmatch(version)
        if exact is None:
            parsed.not_checked.append(f"{name} (version {version})")
            continue
        parsed.dependencies.append(Dependency("Maven", name, exact.group("v"), line))
    return parsed


_GRADLE = re.compile(r"(?P<group>[^:\s#=]+):(?P<artifact>[^:\s=]+):(?P<version>[^\s=]+)=")


def parse_gradle_lockfile(text: str) -> Parsed:
    parsed = Parsed()
    seen: set[tuple[str, str]] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _GRADLE.match(raw)
        if match is None:
            continue
        found = (f"{match.group('group')}:{match.group('artifact')}", match.group("version"))
        if found not in seen:
            seen.add(found)
            parsed.dependencies.append(Dependency("Maven", *found, number))
    return parsed


# ----- Gemfile.lock

_GEM_SPEC = re.compile(r"^ {4}(?P<name>[A-Za-z0-9_.-]+) \((?P<version>[^)\s]+)\)$")


def parse_gemfile_lock(text: str) -> Parsed:
    parsed = Parsed()
    section: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw and not raw[0].isspace():
            section = raw.strip()
            continue
        if section != "GEM":
            continue
        match = _GEM_SPEC.match(raw)
        if match is not None:
            version = match.group("version").split("-", 1)[0]  # drop the platform: 1.15.4-x86_64-linux
            parsed.dependencies.append(Dependency("RubyGems", match.group("name"), version, number))
    return parsed


# ----- packages.lock.json (NuGet)


def parse_nuget_lock(text: str) -> Parsed:
    parsed = Parsed()
    data = _load_json(text, parsed)
    if not isinstance(data, dict):
        return parsed
    frameworks = data.get("dependencies")
    if not isinstance(frameworks, dict):
        return parsed
    find = _line_finder(text)
    seen: set[tuple[str, str]] = set()
    for packages in frameworks.values():
        for name, entry in packages.items() if isinstance(packages, dict) else []:
            version = entry.get("resolved") if isinstance(entry, dict) else None
            if not isinstance(version, str) or entry.get("type") == "Project" or (name, version) in seen:
                continue
            seen.add((name, version))
            parsed.dependencies.append(Dependency("NuGet", name, version, max(find(json.dumps(name) + ":"), 1)))
    return parsed


# ----- pubspec.lock

_PUB_KEY = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_]+):\s*$")
_PUB_FIELD = re.compile(r"^ {4}(?P<key>source|version):\s*[\"']?(?P<value>[^\"'\s]+)[\"']?\s*$")


def parse_pubspec_lock(text: str) -> Parsed:
    parsed = Parsed()
    in_packages = False
    current: tuple[str, int] | None = None
    fields: dict[str, str] = {}
    hosted_url = True

    def flush() -> None:
        if current is not None and fields.get("source") == "hosted" and hosted_url and "version" in fields:
            parsed.dependencies.append(Dependency("Pub", current[0], fields["version"], current[1]))

    for number, raw in enumerate(text.splitlines(), start=1):
        if raw and not raw[0].isspace():
            flush()
            current, fields, hosted_url = None, {}, True
            in_packages = raw.strip() == "packages:"
            continue
        if not in_packages:
            continue
        key = _PUB_KEY.match(raw)
        if key is not None:
            flush()
            current, fields, hosted_url = (key.group("name"), number), {}, True
            continue
        field_match = _PUB_FIELD.match(raw)
        if field_match is not None:
            fields[field_match.group("key")] = field_match.group("value")
        elif raw.strip().startswith("url:") and "pub.dev" not in raw and "pub.dartlang.org" not in raw:
            hosted_url = False  # a private registry: not on pub.dev, so no advisory applies
    flush()
    return parsed


# ----- bun.lock

_BUN_ENTRY = re.compile(r"""^ {4}"[^"]+":\s*\[\s*"(?P<name>(?:@[^/@"]+/)?[^@"]+)@(?P<version>[^"]+)\"""")


def parse_bun_lock(text: str) -> Parsed:
    parsed = Parsed()
    in_packages = False
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.startswith('  "packages"'):
            in_packages = True
            continue
        if in_packages and raw.startswith("  }"):
            in_packages = False
        match = _BUN_ENTRY.match(raw) if in_packages else None
        if match is not None and match.group("version")[:1].isdigit():  # not workspace:, github:, file:, npm: aliases
            parsed.dependencies.append(Dependency("npm", match.group("name"), match.group("version"), number))
    return parsed


def parse_bun_lockb(text: str) -> Parsed:
    return Parsed(
        unsupported="bun.lockb is a binary file; use Bun 1.2 or newer's text lockfile (`bun install --save-text-lockfile`)"
    )


MORE_PARSERS: dict[str, Callable[[str], Parsed]] = {
    "composer.lock": parse_composer_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "Cargo.lock": parse_cargo_lock,
    "pom.xml": parse_pom,
    "gradle.lockfile": parse_gradle_lockfile,
    "Gemfile.lock": parse_gemfile_lock,
    "packages.lock.json": parse_nuget_lock,
    "pubspec.lock": parse_pubspec_lock,
    "bun.lock": parse_bun_lock,
    "bun.lockb": parse_bun_lockb,
}
