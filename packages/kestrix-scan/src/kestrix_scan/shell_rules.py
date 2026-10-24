# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for shell scripts: ``.sh`` and ``.bash`` files, GitHub Actions ``run:`` blocks and Dockerfile ``RUN`` lines.

The shell is not parsed. A script is cut into logical lines (comments removed, ``\\`` continuations joined, here-document
bodies skipped) and each rule matches one command shape on a line:

- ``sh.pipe_to_shell``: ``curl`` or ``wget`` piped into a shell or interpreter, ``sh <(curl ...)`` and
  ``sh -c "$(curl ...)"``;
- ``sh.eval.variable``: ``eval`` of text that holds a variable (``$cmd``, ``"$@"``); ``eval "$(tool init)"`` is left alone;
- ``sh.rm_rf.unguarded_variable``: ``rm -rf`` of a path that is only a variable (``$DIR``, ``"$DIR/"``, ``$DIR/*``) with no
  ``${DIR:?}`` guard, no earlier test of it in the script and no ``mktemp`` assignment;
- ``sh.chmod.world_writable``: ``chmod`` to a mode that lets everyone write (``777``, ``666``, ``a+w``, ``o+w``).

Nothing is run or expanded; a variable the script sets itself is not followed.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from .models import clip_snippet
from .registry import Hit

MAX_LOGICAL_CHARS = 20_000
MAX_SCRIPT_LINES = 30_000

PIPE = "pipe"
EVAL = "eval"
RM = "rm"
CHMOD = "chmod"
ALL_CHECKS = frozenset({PIPE, EVAL, RM, CHMOD})
SH_RULES: Mapping[str, str] = {
    PIPE: "sh.pipe_to_shell",
    EVAL: "sh.eval.variable",
    RM: "sh.rm_rf.unguarded_variable",
    CHMOD: "sh.chmod.world_writable",
}

_SHELL = r"(?:ba|z|da|k|fi|a)?sh"
_SCRIPT_LANG = r"(?:python[0-9.]*|node|perl|ruby)"
_INTERPRETER = rf"(?:{_SHELL}|{_SCRIPT_LANG})"
# a shell reads the piped script unless given -c; python, node, perl and ruby only when they run stdin (no -c, -m, -e, -p)
_STDIN_INTERPRETER = (
    rf"(?:{_SHELL}\b(?![-./\w])(?!\s+-c\b)|{_SCRIPT_LANG}\b(?![-./\w])(?=\s*(?:$|[|;&)>]|-(?:\s|$)|\s-(?:\s|$))))"
)
_FETCH = r"(?:curl|wget)"
_PIPE_TO_SHELL = re.compile(
    rf"\b{_FETCH}\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\w+=\S*\s+)*)?(?:/usr/bin/|/bin/|/usr/local/bin/)?{_STDIN_INTERPRETER}"
)
_SUBSTITUTED = re.compile(
    rf"(?:\b{_INTERPRETER}\s+(?:-\w+\s+)*|\beval\s+|\bsource\s+|(?<![\w.])\.\s+)[\"']?(?:<\(|\$\()\s*{_FETCH}\b"
)
_COMMAND_START = r"(?:^|[;&|(`{]|\b(?:then|do|else|elif)\b|\$\()\s*"
_EVAL = re.compile(_COMMAND_START + r"eval\s+(?P<arg>\S.*)$")
_SUBSTITUTION = re.compile(r"\$\([^$()]*\)|`[^`$]*`")
_VARIABLE = re.compile(r"(?<!\\)\$(?:[A-Za-z_]\w*|\{[A-Za-z_@*#?!0-9]|[@*0-9#?!])")
_RM = re.compile(_COMMAND_START + r"(?:sudo\s+)?rm\s+(?P<args>\S.*)$")
_CHMOD = re.compile(_COMMAND_START + r"(?:sudo\s+)?chmod\s+(?P<args>\S.*)$")
# text that is only a string, not a command: single quotes, and double quotes without a command substitution
_LITERAL_QUOTES = re.compile(r"\"(?:[^\"$`\\]|\$(?!\()|\\.)*\"|'[^']*'")
_SINGLE_QUOTED = re.compile(r"'[^']*'")
_TOKEN = re.compile(r"\"[^\"]*\"|'[^']*'|\S+")
_BRACED = re.compile(r"\$\{(?P<name>[A-Za-z_]\w*)(?:(?P<op>:?[-=?+])(?P<arg>[^}]*))?\}")
_BARE = re.compile(r"\$(?P<name>[A-Za-z_]\w*)")
_ALWAYS_SET = frozenset({"HOME", "PWD", "TMPDIR", "TMP", "USER", "AGENT_TOOLSDIRECTORY"})  # plus GITHUB_* and RUNNER_*
# an assignment whose value starts with a literal or a command, not with another variable or nothing
_ASSIGNED = r"(?:^|[;&|(\s])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?{var}=[\"']?(?![\"']?(?:$|[\s;&|)]|\$[{{A-Za-z0-9@*#]))"
_HEREDOC = re.compile(r"<<-?\s*(?P<quote>['\"]?)(?P<tag>[A-Za-z_][\w-]*)(?P=quote)")
_CONTROL = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "2>", "2>&1"})
_SYMBOLIC = re.compile(r"^([ugoa]*)([-+=])([rwxXst]*)$")
_OCTAL = re.compile(r"^[0-7]{3,4}$")


@dataclass(slots=True)
class Logical:
    """One logical line: comments removed, continuations joined; maps offsets back to physical lines."""

    text: str
    offsets: list[int]  # start offset in ``text`` of each physical line
    lines: list[int]  # 1-based physical line numbers
    raws: list[str]

    def at(self, pos: int) -> tuple[int, str]:
        """(physical line number, its stripped text) holding offset ``pos``."""
        i = max(bisect.bisect_right(self.offsets, pos) - 1, 0)
        return self.lines[i], self.raws[i].strip()


def strip_shell_comment(line: str) -> str:
    """``line`` without a trailing shell comment (``#`` at the start or after whitespace, outside quotes)."""
    quote = ""
    i = 0
    while i < len(line):
        char = line[i]
        if quote:
            if char == "\\" and quote == '"':
                i += 1
            elif char == quote:
                quote = ""
        elif char == "\\":
            i += 1
        elif char in "'\"":
            quote = char
        elif char == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            return line[:i]
        i += 1
    return line


def logical_lines(text: str, first_line: int = 1, *, comment: str = "#") -> Iterator[Logical]:
    """Logical lines of a shell script; here-document bodies are skipped."""
    rows = text.splitlines()[:MAX_SCRIPT_LINES]
    i = 0
    while i < len(rows):
        parts: list[str] = []
        offsets: list[int] = []
        numbers: list[int] = []
        raws: list[str] = []
        total = 0
        while i < len(rows):
            raw = rows[i]
            line = strip_shell_comment(raw) if comment == "#" else raw
            joined = line.rstrip().endswith("\\")
            piece = line.rstrip()[:-1] if joined else line
            offsets.append(total)
            numbers.append(first_line + i)
            raws.append(raw)
            parts.append(piece)
            total += len(piece) + 1
            i += 1
            if not joined or total > MAX_LOGICAL_CHARS:
                break
        logical = Logical(" ".join(parts), offsets, numbers, raws)
        yield logical
        match = _HEREDOC.search(logical.text)
        if match is not None and "<<<" not in logical.text[match.start() : match.start() + 3]:
            tag = match.group("tag")
            while i < len(rows) and rows[i].strip() != tag:
                i += 1
            i += 1


def _hit(rule_id: str, logical: Logical, pos: int, message: str, *, cwe: str | None = None) -> Hit:
    line, raw = logical.at(pos)
    return Hit(rule_id=rule_id, line=line, column=1, end_line=line, message=message, snippet=clip_snippet(raw), cwe=cwe)


def _tokens(args: str) -> list[str]:
    out: list[str] = []
    for token in _TOKEN.findall(args):
        if token in _CONTROL or token.startswith(("&", "|", ";", ">", "<", "2>")):
            break
        out.append(token)
    return out


def _guarded_before(name: str, earlier: str) -> bool:
    """True when the script already tests ``name`` or sets it from ``mktemp`` before the ``rm``."""
    var = re.escape(name)
    return bool(
        re.search(rf"(?:-[nzd]\s+[\"']?\$\{{?{var}\b|\$\{{{var}:?\?|{var}=[\"']?(?:\$\(|`)\s*mktemp)", earlier)
        or re.search(rf"\[\[?\s+[\"']?\$\{{?{var}[\"']?\s+\]", earlier)
        or re.search(
            _ASSIGNED.format(var=var), earlier, re.M
        )  # set from a literal or a command, not from another variable
        or re.search(rf"\bfor\s+{var}\s+in\b", earlier)
    )


def _unguarded_rm_target(token: str, earlier: str) -> str | None:
    """The variable name when ``token`` is nothing but an unguarded variable (``$D``, ``"${D}/"``, ``$D/*``)."""
    if token.startswith("'"):
        return None
    inner = token[1:-1] if token.startswith('"') and token.endswith('"') and len(token) >= 2 else token
    for pattern in (_BRACED, _BARE):
        match = pattern.match(inner)
        if match is None:
            continue
        if inner[match.end() :] not in ("", "/", "/*", "/.*", "/."):
            return None
        name = match.group("name")
        if name in _ALWAYS_SET or name.startswith(("GITHUB_", "RUNNER_")):
            return None
        if pattern is _BRACED and match.group("op") is not None:
            op, arg = match.group("op"), match.group("arg")
            if op.endswith("?") or arg:
                return None
        return None if _guarded_before(name, earlier) else name
    return None


def _recursive_force(flags: list[str]) -> bool:
    recursive = force = False
    for flag in flags:
        if flag == "--recursive":
            recursive = True
        elif flag == "--force":
            force = True
        elif flag.startswith("-") and not flag.startswith("--"):
            recursive = recursive or "r" in flag or "R" in flag
            force = force or "f" in flag
    return recursive and force


def _world_writable(mode: str) -> bool:
    if _OCTAL.match(mode):
        sticky = len(mode) == 4 and int(mode[0]) & 1 != 0  # 1777 on a shared directory is the intended mode
        return int(mode[-1]) & 2 != 0 and not sticky
    for clause in mode.split(","):
        match = _SYMBOLIC.match(clause)
        if match is None:
            return False
        who, op, perms = match.groups()
        if op != "-" and "w" in perms and ("o" in who or "a" in who):
            return True
    return False


def scan_logical(
    logical: Logical, start: int, checks: frozenset[str], earlier: list[str], rule_ids: Mapping[str, str] = SH_RULES
) -> list[Hit]:
    """Hits in ``logical.text[start:]`` for the named checks; ``earlier`` holds the script's earlier logical lines."""
    text = logical.text[start:]
    hits: list[Hit] = []
    if PIPE in checks:
        match = _PIPE_TO_SHELL.search(
            _LITERAL_QUOTES.sub(lambda m: " " * len(m.group(0)), text)
        ) or _SUBSTITUTED.search(text)
        if match is not None:
            hits.append(
                _hit(
                    rule_ids[PIPE],
                    logical,
                    start + match.start(),
                    "Downloads with curl or wget and runs the result in a shell or interpreter without checking it.",
                )
            )
    if EVAL in checks and (match := _EVAL.search(text)) is not None:
        # variables inside single quotes expand only after eval has parsed the text, so their values are not parsed as code
        argument = _SUBSTITUTION.sub("", _SINGLE_QUOTED.sub("", match.group("arg")))
        # an escaped \$ is the indirect-expansion idiom (eval echo \$$name): the name, not the value, is evaluated
        if _VARIABLE.search(argument) and "\\$" not in argument:
            hits.append(
                _hit(
                    rule_ids[EVAL],
                    logical,
                    start + match.start("arg"),
                    "eval runs text that contains a variable, so whatever the variable holds becomes shell code.",
                )
            )
    if RM in checks and (match := _RM.search(text)) is not None:
        tokens = _tokens(match.group("args"))
        flags = [t for t in tokens if t.startswith("-")]
        if _recursive_force(flags):
            before = "\n".join(earlier) + "\n" + text[: match.start()]
            for token in (t for t in tokens if not t.startswith("-") and t != "--"):
                name = _unguarded_rm_target(token, before)
                if name is not None:
                    hits.append(
                        _hit(
                            rule_ids[RM],
                            logical,
                            start + match.start("args"),
                            f"rm -rf of ${name} with no guard: when ${name} is empty or unset the command deletes the "
                            "wrong tree (the current directory's parent chain, or / for a trailing slash).",
                        )
                    )
                    break
    if CHMOD in checks and (match := _CHMOD.search(text)) is not None:
        tokens = [t.strip("\"'") for t in _tokens(match.group("args")) if not t.startswith("-")]
        if tokens and _world_writable(tokens[0]):
            hits.append(
                _hit(
                    rule_ids[CHMOD],
                    logical,
                    start + match.start("args"),
                    f"chmod {tokens[0]} lets every user on the machine change the file or directory.",
                )
            )
    return hits


def shell_hits(text: str, first_line: int = 1, *, checks: frozenset[str] = ALL_CHECKS) -> list[Hit]:
    """Shell rule hits for a script (a ``.sh`` file or one ``run:`` block whose first line is ``first_line``)."""
    hits: list[Hit] = []
    seen: list[str] = []
    for logical in logical_lines(text, first_line):
        if logical.text.strip():
            hits.extend(scan_logical(logical, 0, checks, seen))
            seen.append(logical.text)
    return hits


def check_shell(text: str) -> list[Hit]:
    return shell_hits(text)
