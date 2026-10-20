# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for Claude Code and MCP configuration files (``config.*``).

Files, by path relative to the scan root:

- ``.claude/settings.json`` and ``.claude/settings.local.json``: ``hooks``, ``permissions``
  (``defaultMode``, ``allow``), ``enableAllProjectMcpServers`` and ``env``;
- ``hooks/hooks.json`` (a plugin's hooks): ``hooks``;
- ``.mcp.json``: ``mcpServers`` with ``command``, ``args``, ``env``, ``url`` and ``headers``.

The field names follow https://code.claude.com/docs/en/settings, /hooks, /permissions and /mcp.
A repository's configuration is untrusted input: it is parsed with the standard-library ``json``
after a size check, only strings, lists and objects are read from it, and nothing in it is run or
expanded. Secret values never leave this module; a hit carries the kind and a redacted prefix.
JSON has no comments, so these findings cannot be suppressed inline; use ``rules.disable`` or a
baseline.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from typing import Any

from .models import Severity, SkipReason, clip_snippet
from .registry import RULES, Hit
from .secrets import detect, redacted

MAX_CONFIG_BYTES = 256 * 1024
MAX_ITEMS = 500  # hooks, rules, servers or values read per list or object

_BROAD_SHELL_RULES = frozenset({"bash", "bash(*)", "bash(:*)", "bash(**)", "powershell", "powershell(*)"})
_FETCH = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
_INTERPRETER = r"(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby|iex|invoke-expression|pwsh|powershell)"
_PIPE_TO_SHELL = re.compile(
    rf"(?i)\b{_FETCH}\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:/usr/bin/|/bin/|/usr/local/bin/)?{_INTERPRETER}\b"
)
_SUBSTITUTED = re.compile(
    rf"(?i)(?:\b{_INTERPRETER}\s+(?:-c\s+)?|\beval\s+|\bsource\s+|\.\s+)[\"']?[<$]\(\s*{_FETCH}\b"
)
_DOWNLOAD_TO = re.compile(
    rf"(?i)\b{_FETCH}\b[^;&|\n]*?\s(?:-o|-O|--output|--output-document|-OutFile)[ =]?\s*([^\s;&|]+)"
)
_RUN_FILE = r"(?:&&|;|\|\|)\s*(?:sudo\s+)?(?:(?:{interp})\s+|chmod\s+\+x\s+|source\s+|\.\s+)?\S*{name}\b"
_PINNED_NPM = re.compile(r"^(?:@[^/@\s]+/)?[^@\s]+@v?\d")
_PINNED_PY = re.compile(r"(?:==|@v?)\d")
_UVX_VALUE_FLAGS = frozenset(
    {"--from", "--with", "--python", "-p", "--index-url", "--extra-index-url", "--index", "-w"}
)


def config_kind(rel: str) -> str | None:
    """'settings', 'plugin_hooks' or 'mcp' for a configuration file this module reads, else None."""
    parts = rel.split("/")
    name, parent = parts[-1], parts[-2] if len(parts) > 1 else ""
    if parent == ".claude" and name in ("settings.json", "settings.local.json"):
        return "settings"
    if parent == "hooks" and name == "hooks.json":
        return "plugin_hooks"
    if name == ".mcp.json":
        return "mcp"
    return None


def check_config(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one configuration file, or why it could not be analyzed."""
    kind = config_kind(rel)
    if kind is None:
        return []
    if len(text.encode("utf-8", "replace")) > MAX_CONFIG_BYTES:
        return "too_large"
    try:
        data = json.loads(text)
    except ValueError:
        return "syntax_error"
    except RecursionError:
        return "too_complex"
    if not isinstance(data, dict):
        return []
    checker = _Config(text)
    if kind in ("settings", "plugin_hooks"):
        checker.hooks(data.get("hooks"))
    if kind == "settings":
        checker.permissions(data)
        checker.env(data.get("env"))
    if kind == "mcp":
        checker.servers(data.get("mcpServers"))
    return checker.hits


def _items(value: Any) -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        yield from list(value.items())[:MAX_ITEMS]


def _list(value: Any) -> list[Any]:
    return value[:MAX_ITEMS] if isinstance(value, list) else []


def remote_exec(command: str) -> bool:
    """True when a shell command runs something it downloads: curl ... | sh, sh <(curl ...), or download then run."""
    if _PIPE_TO_SHELL.search(command) or _SUBSTITUTED.search(command):
        return True
    for match in _DOWNLOAD_TO.finditer(command):
        target = os.path.basename(match.group(1).strip("'\""))
        if target and target != "-":
            after = command[match.end() :]
            if re.search(_RUN_FILE.format(interp=_INTERPRETER, name=re.escape(target)), after, re.I):
                return True
    return False


def unpinned_package(command: str, args: list[str]) -> str | None:
    """The package an ``npx -y`` or ``uvx`` launcher runs without a pinned version, or None."""
    tokens = [*command.split(), *args]
    if len(tokens) > 2 and os.path.basename(tokens[0]).lower() in ("cmd", "cmd.exe") and tokens[1].lower() == "/c":
        tokens = tokens[2:]
    if not tokens:
        return None
    launcher = os.path.basename(tokens[0]).lower().removesuffix(".cmd").removesuffix(".exe")
    rest = tokens[1:]
    if launcher == "npx":
        if not {"-y", "--yes"} & set(rest):
            return None
        package = _npx_package(rest)
        return package if package is not None and not _PINNED_NPM.match(package) else None
    if launcher == "uvx" or (launcher == "uv" and rest[:2] == ["tool", "run"]):
        package = _uvx_package(rest[2:] if launcher == "uv" else rest)
        return package if package is not None and not _PINNED_PY.search(package) else None
    return None


def _npx_package(args: list[str]) -> str | None:
    for i, arg in enumerate(args):
        if arg in ("-p", "--package") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--package="):
            return arg.split("=", 1)[1]
    return next((arg for arg in args if not arg.startswith("-")), None)


def _uvx_package(args: list[str]) -> str | None:
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg == "--from" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--from="):
            return arg.split("=", 1)[1]
        if arg in _UVX_VALUE_FLAGS:
            skip = True
        elif not arg.startswith("-"):
            return arg
    return None


class _Config:
    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.splitlines()
        self.hits: list[Hit] = []

    def _locate(self, needle: str) -> tuple[int, int]:
        """1-based line and column of ``needle`` as written in the JSON text (first occurrence), else (1, 1)."""
        for form in (json.dumps(needle, ensure_ascii=False)[1:-1], json.dumps(needle)[1:-1], needle):
            index = self.text.find(form) if form else -1
            if index >= 0:
                line = self.text.count("\n", 0, index) + 1
                return line, index - (self.text.rfind("\n", 0, index) + 1) + 1
        return 1, 1

    def hit(
        self, rule_id: str, needle: str, message: str, *, snippet: str | None = None, severity: Severity | None = None
    ) -> None:
        line, column = self._locate(needle)
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        self.hits.append(
            Hit(
                rule_id=rule_id,
                line=line,
                column=column,
                end_line=line,
                message=message,
                snippet=snippet if snippet is not None else clip_snippet(text),
                severity=severity,
            )
        )

    # ----- settings and plugin hooks

    def hooks(self, hooks: Any) -> None:
        for event, groups in _items(hooks):
            for group in _list(groups):
                handlers = group.get("hooks") if isinstance(group, dict) else None
                for handler in _list(handlers):
                    if not isinstance(handler, dict) or handler.get("type", "command") != "command":
                        continue
                    command = handler.get("command")
                    if not isinstance(command, str):
                        continue
                    args = [a for a in _list(handler.get("args")) if isinstance(a, str)]
                    if remote_exec(" ".join([command, *args])):
                        self.hit(
                            "config.claude.hook_remote_exec",
                            command,
                            f"The {event} hook runs a script it downloads when it runs, without a pinned version or checksum.",
                        )

    def permissions(self, settings: dict[str, Any]) -> None:
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            if permissions.get("defaultMode") == "bypassPermissions":
                self.hit(
                    "config.claude.permissions_bypass",
                    "bypassPermissions",
                    "permissions.defaultMode is bypassPermissions. Claude Code 2.1.257 and newer ignore it in project "
                    "settings, but older versions start every session without permission prompts.",
                )
            for rule in _list(permissions.get("allow")):
                if isinstance(rule, str) and rule.replace(" ", "").lower() in _BROAD_SHELL_RULES:
                    self.hit(
                        "config.claude.permissions_bypass",
                        rule,
                        f"The allow rule {rule!r} lets Claude run every shell command without asking.",
                    )
        if settings.get("enableAllProjectMcpServers") is True:
            self.hit(
                "config.claude.permissions_bypass",
                "enableAllProjectMcpServers",
                "enableAllProjectMcpServers approves every server in the project's .mcp.json without a prompt.",
            )

    def env(self, env: Any) -> None:
        for name, value in _items(env):
            if isinstance(value, str):
                self._secret("config.claude.env_leak", f"settings env {name}", name, value)

    # ----- .mcp.json

    def servers(self, servers: Any) -> None:
        for server_name, server in _items(servers):
            if not isinstance(server, dict):
                continue
            command = server.get("command")
            args = [a for a in _list(server.get("args")) if isinstance(a, str)]
            if isinstance(command, str):
                package = unpinned_package(command, args)
                if package is not None:
                    self.hit(
                        "config.mcp.unpinned_launcher",
                        package,
                        f"MCP server {server_name!r} runs the latest {package!r} at every start (no pinned version).",
                    )
            for name, value in _items(server.get("env")):
                if isinstance(value, str):
                    self._secret("config.mcp.secret_inline", f"{server_name} env {name}", name, value)
            for name, value in _items(server.get("headers")):
                if isinstance(value, str):
                    token = value.split(None, 1)[1] if value.lower().startswith(("bearer ", "token ")) else value
                    self._secret("config.mcp.secret_inline", f"{server_name} header {name}", f"{name} token", token)
            previous = ""
            for arg in args:
                self._secret("config.mcp.secret_inline", f"{server_name} args", previous.lstrip("-"), arg)
                previous = arg
            url = server.get("url")
            if isinstance(url, str):
                self._secret("config.mcp.secret_inline", f"{server_name} url", "", url)

    def _secret(self, rule_id: str, where: str, name: str, value: str) -> None:
        if "${" in value:
            return  # an environment-variable reference, which is the fix
        found = detect(value, name)
        if found is None:
            return
        kind, secret = found
        label = redacted(kind, secret)
        self.hit(
            rule_id,
            secret,
            f"{where} holds a literal {kind.replace('_', ' ')} ({label}).",
            snippet=label,
            severity=RULES[f"secret.{kind}"].severity,
        )
