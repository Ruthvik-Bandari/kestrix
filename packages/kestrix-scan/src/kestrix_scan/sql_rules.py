# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for ``.sql`` files (``sql.*``): over-broad grants, plaintext account passwords and PostgreSQL
``SECURITY DEFINER`` functions without a fixed ``search_path``. Source is never run.

A small bounded reader splits the file into statements at ``;`` outside string literals (``'...'``, ``"..."``,
```...```), dollar-quoted bodies (``$$ ... $$``, ``$tag$ ... $tag$``) and comments (``-- ...``, ``/* ... */``, and
MySQL's ``# ...``). Comments are removed, literals are kept, and each statement keeps the line it starts on. A file is
skipped as ``too_complex`` past ``MAX_STATEMENTS``. Every scan step advances, so the work is linear in the file size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import SkipReason, clip_snippet
from .registry import Hit

SQL_SUFFIXES = frozenset({".sql"})
MAX_STATEMENTS = 200_000
MAX_AVERAGE_LINE = 2000

_TOKEN = re.compile(
    r"""
      (?P<line>--[^\n]*|\#[^\n]*)
    | (?P<block>/\*.*?(?:\*/|\Z))
    | (?P<single>'(?:[^']|'')*(?:'|\Z))
    | (?P<double>"(?:[^"]|"")*(?:"|\Z))
    | (?P<tick>`[^`]*(?:`|\Z))
    | (?P<dollar>\$(?:[A-Za-z_]\w*)?\$)
    | (?P<semi>;)
    """,
    re.VERBOSE | re.DOTALL,
)
_GRANT_ALL = re.compile(r"^\s*GRANT\s+ALL(?:\s+PRIVILEGES)?\b(?P<rest>.*)$", re.IGNORECASE | re.DOTALL)
_WIDE_TARGET = re.compile(r"\bON\s+(?:\*\s*\.\s*\*|`?\*`?\s*\.\s*`?\*`?)|\bTO\s+PUBLIC\b", re.IGNORECASE)
_DATABASE_TARGET = re.compile(
    r"\bON\s+(?:DATABASE\b|ALL\s+(?:TABLES|SEQUENCES|FUNCTIONS)\b|SCHEMA\b|`?[\w$]+`?\s*\.\s*\*)", re.IGNORECASE
)
_CREATE_ACCOUNT = re.compile(r"^\s*(?:CREATE|ALTER)\s+(?:OR\s+REPLACE\s+)?(?:USER|ROLE|LOGIN|GROUP)\b", re.IGNORECASE)
_PASSWORD = re.compile(
    r"""(?:\bIDENTIFIED\s+(?:WITH\s+\w+\s+)?BY\s+(?!PASSWORD\b)|\bPASSWORD\s+(?:=\s*)?|\bWITH\s+PASSWORD\s+|\bBY\s+)
        '(?P<secret>(?:[^']|'')*)'""",
    re.IGNORECASE | re.VERBOSE,
)
_HASHED = re.compile(r"\bIDENTIFIED\s+(?:WITH\s+\w+\s+)?(?:BY\s+PASSWORD|AS)\s+'(?:[^']|'')*'", re.IGNORECASE)
_SET_PASSWORD = re.compile(
    r"^\s*SET\s+PASSWORD\b.*?=\s*(?:PASSWORD\s*\(\s*)?'(?P<secret>(?:[^']|'')*)'", re.IGNORECASE | re.DOTALL
)
_FUNCTION = re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b", re.IGNORECASE)
_DEFINER = re.compile(r"\bSECURITY\s+DEFINER\b", re.IGNORECASE)
_MYSQL_PREFIX = re.compile(r"(?<!\bLANGUAGE\s)\bSQL\s+$", re.IGNORECASE)
_LANGUAGE = re.compile(r"\bLANGUAGE\s+\w+", re.IGNORECASE)
_SEARCH_PATH = re.compile(r"\bsearch_path\b", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"^(?:|<[^>]*>|\$\{[^}]*\}|\$\d+|\{\{[^}]*\}\}|%s|\?|:\w+|@\w+|\*+|x{3,}|\.{3,}|\*[0-9A-Fa-f]{40}|md5[0-9a-f]{32}"
    r"|SCRAM-SHA-256\$.*|\$(?:2[aby]|argon2\w*|pbkdf2\S*)\$.*|\*\*\*.*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Statement:
    text: str  # comments removed (replaced by a space), literals kept
    line: int  # 1-based line of the first non-blank character


def statements(text: str) -> list[_Statement] | None:
    """Statements of an SQL file, or None past ``MAX_STATEMENTS``."""
    out: list[_Statement] = []
    parts: list[str] = []
    first = 0  # offset of the first non-blank character of the statement being read
    started = False
    pos = 0
    n = len(text)
    counted = 0  # lines are counted incrementally: the statement starts only move forward
    line = 1

    def emit() -> None:
        nonlocal parts, started, counted, line
        statement = "".join(parts)
        if statement.strip():
            line += text.count("\n", counted, first)
            counted = first
            out.append(_Statement(statement, line))
        parts = []
        started = False

    while pos < n:
        match = _TOKEN.search(text, pos)
        stop = match.start() if match else n
        chunk = text[pos:stop]
        if not started and chunk.strip():
            first = pos + len(chunk) - len(chunk.lstrip())
            started = True
        parts.append(chunk)
        if match is None:
            break
        kind = match.lastgroup
        token = match.group(0)
        end = match.end()
        if kind in ("line", "block"):
            parts.append(" ")
        elif kind == "semi":
            emit()
            if len(out) > MAX_STATEMENTS:
                return None
        else:
            if not started:
                first = match.start()
                started = True
            if kind == "tag" or match.group("dollar") is not None:
                closing = text.find(token, end)
                end = n if closing < 0 else closing + len(token)
                token = text[match.start() : end]
            parts.append(token)
        pos = end
    emit()
    return out


def check_sql(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one SQL file, or the reason it was not analyzed."""
    if len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE:
        return "minified"
    found = statements(text)
    if found is None:
        return "too_complex"
    lines = text.splitlines()
    hits: list[Hit] = []
    for statement in found:
        hits.extend(_grant(statement, lines))
        hits.extend(_credentials(statement, lines))
        hits.extend(_definer(statement, lines))
    return hits


def _hit(rule_id: str, statement: _Statement, lines: list[str], message: str, severity: str | None = None) -> Hit:
    source = lines[statement.line - 1] if 0 < statement.line <= len(lines) else ""
    return Hit(
        rule_id,
        statement.line,
        1,
        statement.line + statement.text.strip().count("\n"),
        message,
        clip_snippet(source),
        severity=severity,  # type: ignore[arg-type]
    )


def _grant(statement: _Statement, lines: list[str]) -> list[Hit]:
    match = _GRANT_ALL.match(statement.text)
    if match is None:
        return []
    rest = match.group("rest")
    if _WIDE_TARGET.search(rest):
        severity: str | None = None
        message = "GRANT ALL on every database (or to PUBLIC) gives the account every privilege."
    elif _DATABASE_TARGET.search(rest):
        severity = "medium"
        message = "GRANT ALL on a whole database or schema gives the account every privilege on it."
    else:
        severity = "low"
        message = "GRANT ALL gives the account every privilege on this object."
    return [_hit("sql.grant.all", statement, lines, message, severity)]


def _credentials(statement: _Statement, lines: list[str]) -> list[Hit]:
    text = _HASHED.sub(" ", statement.text)
    secrets: list[str] = []
    if _CREATE_ACCOUNT.match(text):
        secrets = [m.group("secret") for m in _PASSWORD.finditer(text)]
    else:
        match = _SET_PASSWORD.match(text)
        if match is not None:
            secrets = [match.group("secret")]
    for secret in secrets:
        if _PLACEHOLDER.match(secret.replace("''", "'")):
            continue
        return [
            _hit(
                "sql.credentials.plaintext",
                statement,
                lines,
                "This statement sets an account password to a literal in the file.",
            )
        ]
    return []


def _definer(statement: _Statement, lines: list[str]) -> list[Hit]:
    text = statement.text
    if not _FUNCTION.match(text) or not _LANGUAGE.search(text):
        return []
    if not any(not _MYSQL_PREFIX.search(text[: m.start()]) for m in _DEFINER.finditer(text)):
        return []  # none, or only MySQL's "SQL SECURITY DEFINER"
    if _SEARCH_PATH.search(text):
        return []
    return [
        _hit(
            "sql.function.security_definer_path",
            statement,
            lines,
            "This SECURITY DEFINER function does not set search_path, so it resolves names through the caller's path.",
        )
    ]
