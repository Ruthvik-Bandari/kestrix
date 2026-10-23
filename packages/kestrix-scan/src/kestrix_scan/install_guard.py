# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The Claude Code install guard: check packages a Bash command is about to install, offline.

Recognized commands (after ``&&``, ``;``, ``|`` and newlines split the command line, and leading
``VAR=value``, ``sudo`` and ``env`` are dropped): ``pip install``, ``pip3 install``,
``python -m pip install``, ``uv pip install``, ``uv add``, ``npm install``/``npm i``/``npm add``,
``pnpm add``, ``yarn add``, ``bun add``, ``composer require``, ``go get``/``go install``, ``cargo add``,
``gem install`` and ``dotnet add package``. Requirement files (``-r``), editable installs (``-e``), URLs, paths
and VCS references are skipped, as is any segment ``shlex`` cannot split.

Decisions, from the local OSV index only (see ``osvdb``):

- a package version that a ``MAL-`` advisory (or a GitHub-reviewed malware advisory, CWE-506) covers, or an unpinned package that a ``MAL-``
  advisory covers in every version, gets ``permissionDecision: "deny"`` with the reason;
- an exactly pinned version with known vulnerabilities, or an unpinned package with some
  malicious versions, gets a non-blocking ``additionalContext`` warning that names the fixed version;
- when the index is older than the allowed age (``db-max-age-days``, default 7), the context also says the
  result may be stale; when it holds no data for a requested ecosystem, the context says that package was not
  checked and names the ``db update --ecosystem`` command;
- anything else, no index, ``KESTRIX_INSTALL_GUARD=0`` or ``[tool.kestrix] claude.install-guard = false``
  gets no output. Errors are the caller's to swallow: the hook fails open.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import osvdb
from .config import Config, discover
from .deps import describe_ids, freshness_line, group_fixes, vulnerabilities
from .errors import Rejected
from .versions import all_versions, highest, is_affected, next_fixed

ENV_SWITCH = "KESTRIX_INSTALL_GUARD"
MAX_COMMAND_CHARS = 20_000
MAX_PACKAGES = 50
MAX_MESSAGE_CHARS = 2_000
EMBEDDED_MALWARE_CWE = (
    "CWE-506"  # GitHub-reviewed malware and compromised-release advisories (GHSA-) carry this, not a MAL- id
)


@dataclass(frozen=True, slots=True)
class Requested:
    ecosystem: str  # an OSV ecosystem: 'PyPI', 'npm', 'Packagist', 'Go', 'crates.io', 'RubyGems' or 'NuGet'
    name: str
    version: str | None  # an exact pin, or None


_OPERATORS = frozenset("();<>|&")
_PIP_VALUE_OPTIONS = frozenset(
    {
        "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint", "-t", "--target",
        "--prefix", "--root", "--python-version", "--platform", "--implementation", "--abi", "--src",
        "--upgrade-strategy", "--progress-bar", "--trusted-host", "--cert", "--client-cert", "--proxy",
        "--timeout", "--retries", "--log", "--python", "-p", "--group", "--optional", "--extra", "--package",
        "--index", "--default-index", "--script", "--tag", "--branch", "--rev", "--config-settings", "-C",
        "--only-binary", "--no-binary", "--report", "--dry-run-output",
    }
)  # fmt: skip
_PIP_SKIP_OPTIONS = frozenset({"-r", "--requirement", "-e", "--editable"})
_NPM_VALUE_OPTIONS = frozenset(
    {"--registry", "--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig", "--omit", "--include", "--cwd"}
)
_PIP_SPEC = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?(?:(?P<op>===?)(?P<version>[A-Za-z0-9!+._-]+)|[<>=!~].*)?"
)
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*")
_PYTHON = re.compile(r"(?:.*/)?(?:python(?:3(?:\.\d+)?)?|py)")
_PIP = re.compile(r"(?:.*/)?pip(?:3(?:\.\d+)?)?")


def _segments(command: str) -> list[list[str]]:
    """The simple commands of a command line, as argument lists; segments shlex cannot split are left out."""
    found: list[list[str]] = []
    for line in command.splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError:
            continue
        current: list[str] = []
        for token in tokens:
            if token and set(token) <= _OPERATORS:
                if current:
                    found.append(current)
                current = []
            else:
                current.append(token)
        if current:
            found.append(current)
    return found


def _strip_prefix(args: list[str]) -> list[str]:
    while args and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", args[0]) or args[0] in ("sudo", "env", "command")):
        args = args[1:]
    return args


def _install_args(args: list[str]) -> tuple[str, list[str]] | None:
    """(ecosystem, the arguments after the install verb) for a recognized install command."""
    args = _strip_prefix(args)
    if len(args) >= 3 and _PYTHON.fullmatch(args[0]) and args[1] == "-m" and args[2] == "pip":
        args = ["pip", *args[3:]]
    if len(args) >= 2 and _PIP.fullmatch(args[0]) and args[1] == "install":
        return "PyPI", args[2:]
    if len(args) >= 3 and args[0] == "uv" and args[1] == "pip" and args[2] == "install":
        return "PyPI", args[3:]
    if len(args) >= 2 and args[0] == "uv" and args[1] == "add":
        return "PyPI", args[2:]
    if len(args) >= 2 and args[0] == "npm" and args[1] in ("install", "i", "add"):
        return "npm", args[2:]
    if len(args) >= 2 and args[0] in ("pnpm", "yarn", "bun") and args[1] == "add":
        return "npm", args[2:]
    if len(args) >= 2 and args[0] == "composer" and args[1] in ("require", "req", "r"):
        return "Packagist", args[2:]
    if len(args) >= 2 and args[0] == "go" and args[1] in ("get", "install"):
        return "Go", args[2:]
    if len(args) >= 2 and args[0] == "cargo" and args[1] == "add":
        return "crates.io", args[2:]
    if len(args) >= 2 and args[0] == "gem" and args[1] == "install":
        return "RubyGems", args[2:]
    if len(args) >= 3 and args[0] == "dotnet" and args[1] == "add" and "package" in args[2:]:
        return "NuGet", args[args.index("package", 2) + 1 :]
    return None


def _operands(args: list[str], value_options: frozenset[str]) -> list[str]:
    operands = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            skip_next = arg in value_options or arg in _PIP_SKIP_OPTIONS
            continue
        operands.append(arg)
    return operands


def _pip_spec(spec: str) -> Requested | None:
    if any(mark in spec for mark in ("://", "/", "\\", "@", ";")) or spec.startswith((".", "~")):
        return None
    match = _PIP_SPEC.fullmatch(spec.strip())
    if match is None or spec.endswith((".whl", ".zip", ".tar.gz")):
        return None
    version = match.group("version") if match.group("op") and "*" not in (match.group("version") or "*") else None
    return Requested("PyPI", match.group("name"), version)


def _npm_spec(spec: str) -> Requested | None:
    if "://" in spec or spec.startswith((".", "/", "~")) or spec.endswith((".tgz", ".tar.gz")):
        return None
    at = spec.find("@", 1)
    name, version = (spec[:at], spec[at + 1 :]) if at > 0 else (spec, "")
    if not _NPM_NAME.fullmatch(name) or ":" in version or "/" in version:
        return None
    exact = (
        version
        if version and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version)
        else None
    )
    return Requested("npm", name, exact)


_EXACT = re.compile(r"v?\d+\.\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_COMPOSER_VALUE_OPTIONS = frozenset({"-d", "--working-dir"})
_GO_VALUE_OPTIONS = frozenset({"-C", "-modfile", "-mod", "-tags", "-ldflags", "-o", "-gcflags"})
_CARGO_VALUE_OPTIONS = frozenset(
    {"-F", "--features", "--git", "--path", "--registry", "--rename", "--manifest-path", "-p", "--package",
     "--branch", "--tag", "--rev", "--target", "--config", "-Z"}
)  # fmt: skip
_GEM_VALUE_OPTIONS = frozenset(
    {"-i", "--install-dir", "-n", "--bindir", "-s", "--source", "--platform", "-P", "--trust-policy", "--config-file",
     "--build-root", "--file", "-g", "--without", "--http-proxy", "--user-install"}
)  # fmt: skip
_DOTNET_VALUE_OPTIONS = frozenset({"-f", "--framework", "-s", "--source", "--package-directory", "-pd"})
_COMPOSER_NAME = re.compile(r"[A-Za-z0-9](?:[_.-]?[A-Za-z0-9]+)*/[A-Za-z0-9](?:[_.-]?[A-Za-z0-9]+)*")
_GO_MODULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*\.[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~+-]+)*")
_CRATE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_GEM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_NUGET_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


def _option_value(args: list[str], names: tuple[str, ...]) -> str | None:
    """The value of ``-v 1.2.3``, ``--version 1.2.3`` or ``--version=1.2.3``, or None."""
    for index, arg in enumerate(args):
        if arg in names and index + 1 < len(args):
            return args[index + 1]
        for name in names:
            if name.startswith("--") and arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return None


def _exact(version: str | None) -> str | None:
    return version if version is not None and _EXACT.fullmatch(version) else None


def _composer_specs(args: list[str]) -> list[Requested | None]:
    specs: list[Requested | None] = []
    for operand in _operands(args, _COMPOSER_VALUE_OPTIONS):
        name, version = (
            operand.split(":", 1) if ":" in operand else operand.split("=", 1) if "=" in operand else (operand, "")
        )
        if _COMPOSER_NAME.fullmatch(name):
            specs.append(Requested("Packagist", name, _exact(version)))
        elif specs and specs[-1] is not None and specs[-1].version is None and _exact(operand):
            last = specs[-1]  # `composer require vendor/pkg 1.2.3`
            specs[-1] = Requested(last.ecosystem, last.name, _exact(operand))
    return specs


def _go_specs(args: list[str]) -> list[Requested | None]:
    specs: list[Requested | None] = []
    for operand in _operands(args, _GO_VALUE_OPTIONS):
        name, _, version = operand.partition("@")
        if "://" in name or not _GO_MODULE.fullmatch(name) or ".." in name:
            continue
        specs.append(Requested("Go", name, _exact(version)))
    return specs


def _cargo_specs(args: list[str]) -> list[Requested | None]:
    if any(arg in ("--git", "--path") or arg.startswith(("--git=", "--path=")) for arg in args):
        return []
    specs: list[Requested | None] = []
    for operand in _operands(args, _CARGO_VALUE_OPTIONS):
        name, _, version = operand.partition("@")
        if _CRATE.fullmatch(name):  # `crate@1.2.3` means ^1.2.3 in cargo; only `crate@=1.2.3` pins one version
            specs.append(Requested("crates.io", name, _exact(version[1:]) if version.startswith("=") else None))
    return specs


def _gem_specs(args: list[str]) -> list[Requested | None]:
    wanted = _option_value(args, ("-v", "--version"))
    specs: list[Requested | None] = []
    for operand in _operands(args, _GEM_VALUE_OPTIONS | {"-v", "--version"}):
        name, _, version = operand.partition(":")
        if _GEM_NAME.fullmatch(name) and not name.endswith(".gem"):
            specs.append(Requested("RubyGems", name, _exact(version or wanted)))
    return specs


def _nuget_specs(args: list[str]) -> list[Requested | None]:
    operands = _operands(args, _DOTNET_VALUE_OPTIONS | {"-v", "--version"})
    if not operands or not _NUGET_NAME.fullmatch(operands[0]):
        return []
    return [Requested("NuGet", operands[0], _exact(_option_value(args, ("-v", "--version"))))]


_SPECS = {
    "Packagist": _composer_specs,
    "Go": _go_specs,
    "crates.io": _cargo_specs,
    "RubyGems": _gem_specs,
    "NuGet": _nuget_specs,
}


def parse_command(command: str) -> list[Requested]:
    """The packages a Bash command installs, in order and without duplicates."""
    found: list[Requested] = []
    for segment in _segments(command[:MAX_COMMAND_CHARS]):
        recognized = _install_args(segment)
        if recognized is None:
            continue
        ecosystem, args = recognized
        if ecosystem == "PyPI":
            specs = [_pip_spec(arg) for arg in _operands(args, _PIP_VALUE_OPTIONS)]
        elif ecosystem == "npm":
            specs = [_npm_spec(arg) for arg in _operands(args, _NPM_VALUE_OPTIONS)]
        else:
            specs = _SPECS[ecosystem](args)
        found.extend(spec for spec in specs if spec is not None and spec not in found)
    return found[:MAX_PACKAGES]


def _label(advisory: osvdb.Advisory) -> str:
    return f"{advisory.id} ({advisory.summary})" if advisory.summary else advisory.id


@dataclass(frozen=True, slots=True)
class Verdict:
    denies: list[str]
    warnings: list[str]
    unchecked: list[str]  # packages whose ecosystem the index holds no data for


def check(requested: list[Requested], ignored: frozenset[str] = frozenset()) -> Verdict | None:
    """The deny reasons and warnings for the requested packages, or None when there is no index."""
    db = osvdb.connect()
    if db is None:
        return None
    denies: list[str] = []
    warnings: list[str] = []
    unchecked: list[str] = []
    covered = {source.ecosystem for source in osvdb.sources(db)}
    try:
        for item in requested:
            if item.ecosystem not in covered:
                unchecked.append(f"{item.name} ({item.ecosystem})")
                continue
            advisories = [
                adv
                for adv in osvdb.advisories_for(db, item.ecosystem, item.name)
                if not ({adv.id, *adv.aliases} & ignored)
            ]
            what = f"{item.name}@{item.version}" if item.version else item.name
            malicious = [adv for adv in advisories if adv.malicious or EMBEDDED_MALWARE_CWE in adv.cwes]
            if item.version is not None:
                bad = [adv for adv in malicious if is_affected(item.ecosystem, item.version, adv.ranges, adv.versions)]
            else:
                bad = [adv for adv in malicious if all_versions(adv.ranges, adv.versions)]
            if bad:
                denies.append(
                    f"{what} ({item.ecosystem}) is reported as a malicious package: {'; '.join(map(_label, bad))}."
                )
                continue
            if item.version is None:
                if malicious:
                    listed = sorted({v for adv in malicious for v in adv.versions})[:10]
                    warnings.append(
                        f"Some versions of {item.name} ({item.ecosystem}) are reported as malicious "
                        f"({', '.join(adv.id for adv in malicious)}; versions {', '.join(listed) or 'see the advisories'}). "
                        "Pin a version that is not listed."
                    )
                continue
            vulnerable = [
                adv for adv in advisories if is_affected(item.ecosystem, item.version, adv.ranges, adv.versions)
            ]
            if vulnerable:
                groups = vulnerabilities(vulnerable)
                fixes = [next_fixed(item.ecosystem, item.version, group_fixes(group, vulnerable)) for group in groups]
                target = highest(item.ecosystem, [fix for fix in fixes if fix is not None])
                unfixed = fixes.count(None)
                if target is None:
                    advice = "no fixed version is published"
                elif unfixed:
                    advice = f"install {item.name} {target} or later instead; {unfixed} of them have no fix yet"
                else:
                    advice = f"install {item.name} {target} or later instead"
                warnings.append(
                    f"{what} ({item.ecosystem}) has {len(groups)} known vulnerability(ies): {describe_ids(groups)}; {advice}."
                )
    finally:
        db.close()
    return Verdict(denies, warnings, unchecked)


def _settings(cwd: str | None) -> Config:
    """The project's settings, or the defaults when there is no project directory or its settings are broken."""
    if not cwd or not os.path.isdir(cwd):
        return Config()
    try:
        return discover(Path(cwd))
    except Rejected:
        return Config()


def guard_response(payload: dict[str, Any]) -> str | None:
    """The PreToolUse hook output for a Bash payload, or None to let the command run unremarked."""
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    if not isinstance(command, str) or os.environ.get(ENV_SWITCH, "").strip() == "0":
        return None
    requested = parse_command(command)
    settings = _settings(cwd) if requested else None
    if settings is None or settings.install_guard is False:
        return None
    result = check(requested, frozenset(key for key, _ in settings.ignore_advisories))
    if result is None:
        return None
    notes = [line for line in (freshness_line(settings.db_max_age_days),) if line]
    if result.unchecked:
        ecosystems = sorted(
            {item.ecosystem for item in requested if f"{item.name} ({item.ecosystem})" in result.unchecked}
        )
        notes.append(
            f"The local index has no data for {', '.join(result.unchecked)}, so it was not checked; "
            f"the user can run `kestrix-scan db update --ecosystem {' '.join(ecosystems)}`."
        )
    footer = " ".join(["Source: the local OSV index (kestrix-scan db update).", *notes])
    if result.denies:
        reason = "\n".join(
            [
                "Kestrix install guard blocked this install:",
                *result.denies,
                "Do not install it or a look-alike name, and tell the user. If they confirm it is a false positive, "
                f"they can add the advisory id to [tool.kestrix] ignore-advisories or set {ENV_SWITCH}=0.",
                footer,
            ]
        )
        output: dict[str, Any] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason[:MAX_MESSAGE_CHARS],
        }
        return json.dumps({"hookSpecificOutput": output})
    if result.warnings or notes:
        context = "\n".join(["Kestrix install guard (not blocking):", *result.warnings, footer])
        return json.dumps(
            {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": context[:MAX_MESSAGE_CHARS]}}
        )
    return None
