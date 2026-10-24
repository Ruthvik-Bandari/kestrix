# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A bounded PHP tokenizer in pure Python. Source is read as text, never run.

It is not a parser. It produces the token stream the structural matcher in ``php_index.py`` needs:

- **Open and close tags.** Text outside ``<?php ... ?>`` (inline HTML) is dropped. ``<?=`` becomes the name ``echo``
  and ``?>`` becomes ``;``, so a template's ``<?= $x ?>`` reads like ``echo $x;``. A file with no ``<?php`` or
  ``<?=`` yields no tokens.
- **Strings.** Single-quoted strings and nowdocs are plain ``str`` tokens. Double-quoted strings, heredocs and
  backtick commands keep their text and the names of the variables they interpolate (``$x``, ``${x}``, ``{$x->y}``;
  an escaped ``\\$`` does not count); a string without a variable is a plain ``str``. An unterminated string or
  heredoc ends at the end of the file.
- **Comments** (``//``, ``#`` and ``/* */``) are dropped. A ``//`` or ``#`` comment ends at the line break or at
  ``?>``. ``#[`` (a PHP 8 attribute) is treated as a ``#`` comment.
- **Variables** (``$name``) are ``var`` tokens with the name only; ``$$x`` is the punctuation ``$`` then ``$x``.
  Names may carry namespace backslashes (``\\Foo\\bar``). Casts such as ``(int)`` are ordinary tokens.

Malformed input never raises. More than ``MAX_TOKENS`` tokens, more than ``MAX_NESTING`` open brackets, or text
over ``MAX_CHARS`` give ``None`` (the file is reported as ``too_complex``). Every scan step advances and each
regular expression runs once per position, so the work is linear in the file size.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

MAX_TOKENS = 500_000
MAX_NESTING = 512
MAX_CHARS = 4_000_000

VAR, NAME, NUM, STR, ISTR, SHELL, PUNCT = "var", "name", "num", "str", "istr", "shell", "punct"


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # one of the constants above
    value: str  # a name, an operator, or a string's raw text without quotes (escapes are not decoded)
    line: int  # 1-based line of the first character
    col: int  # 1-based column
    end_line: int  # 1-based line of the last character
    vars: tuple[str, ...] = ()  # istr and shell: names of the interpolated variables


_OPEN = re.compile(r"<\?(?:php(?=[\s]|$)|=)", re.IGNORECASE)
_CLOSE = "?>"
_WS = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"[^\n\r?]*(?:\?(?!>)[^\n\r?]*)*")
_BLOCK_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.S)
_VAR = re.compile(r"\$([A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*)")
_NAME = re.compile(
    r"\\?[A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*(?:\\[A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*)*"
)
_NUMBER = re.compile(r"0[xX][\da-fA-F_]+|0[bB][01_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?")
_SINGLE = re.compile(r"'[^'\\]*(?:\\[\s\S][^'\\]*)*'?")
_DOUBLE = re.compile(r'"[^"\\]*(?:\\[\s\S][^"\\]*)*"?')
_BACKTICK = re.compile(r"`[^`\\]*(?:\\[\s\S][^`\\]*)*`?")
_HEREDOC = re.compile(r"<<<[ \t]*(?:(')(\w+)'|\"(\w+)\"|(\w+))\r?\n")
_INTERPOLATED = re.compile(r"\\[\s\S]|\$\{?([A-Za-z_][\w]*)")
_PUNCT = re.compile(
    r"<=>|\*\*=|\.\.\.|===|!==|<<=|>>=|\?\?=|\?->|->|=>|::|\+\+|--|\+=|-=|\*=|/=|\.=|%=|&=|\|=|\^=|<<|>>|\*\*"
    r"|==|!=|<>|<=|>=|&&|\|\||\?\?|[(){}\[\];,<>+\-*/%&|^!~?:=.@$\\]"
)
_OPENERS = frozenset("([{")
_CLOSERS = frozenset(")]}")
_CLOSE_BRACKET = {"(": ")", "[": "]", "{": "}"}


def _interpolated(body: str) -> tuple[str, ...]:
    names: list[str] = []
    for match in _INTERPOLATED.finditer(body):
        name = match.group(1)
        if name is not None and name not in names:
            names.append(name)
    return tuple(names)


class _Lexer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.tokens: list[Token] = []
        self.line_starts = [0, *(m.end() for m in re.finditer(r"\r\n|\r|\n", text))]
        self.depth = 0

    def _line(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def emit(self, kind: str, value: str, start: int, end: int, names: tuple[str, ...] = ()) -> None:
        line = self._line(start)
        self.tokens.append(
            Token(kind, value, line, start - self.line_starts[line - 1] + 1, self._line(max(start, end - 1)), names)
        )

    def run(self) -> list[Token] | None:
        if self.n > MAX_CHARS:
            return None
        pos = 0
        text = self.text
        while pos < self.n:
            opened = _OPEN.search(text, pos)  # inline HTML up to the next open tag is dropped
            if opened is None:
                break
            if opened.group(0) == "<?=":
                self.emit(NAME, "echo", opened.start(), opened.end())
            pos = opened.end()
            while pos < self.n:
                if len(self.tokens) > MAX_TOKENS or self.depth > MAX_NESTING:
                    return None
                if text.startswith(_CLOSE, pos):
                    self.emit(PUNCT, ";", pos, pos + 2)
                    pos += 2
                    break
                pos = self._code(pos)
            else:
                break
        return self.tokens

    def _code(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char.isspace():
            match = _WS.match(text, pos)
            return match.end() if match else pos + 1
        if char == "#" or (char == "/" and text.startswith("//", pos)):
            match = _LINE_COMMENT.match(text, pos)
            return max(match.end() if match else pos, pos + 1)
        if char == "/" and text.startswith("/*", pos):
            match = _BLOCK_COMMENT.match(text, pos)
            return match.end() if match else self.n
        if char == "'":
            match = _SINGLE.match(text, pos)
            end = match.end() if match else pos + 1
            raw = text[pos:end]
            body = raw[1:-1] if len(raw) > 1 and raw.endswith("'") else raw[1:]
            self.emit(STR, body, pos, end)
            return end
        if char == '"':
            return self._interpolating(_DOUBLE, '"', STR, ISTR, pos)
        if char == "`":
            return self._interpolating(_BACKTICK, "`", SHELL, SHELL, pos)
        if char == "$":
            match = _VAR.match(text, pos)
            if match:
                self.emit(VAR, match.group(1), pos, match.end())
                return match.end()
        if char == "<" and text.startswith("<<<", pos):
            heredoc = self._heredoc(pos)
            if heredoc is not None:
                return heredoc
        if char.isdigit() or (char == "." and text[pos + 1 : pos + 2].isdigit()):
            match = _NUMBER.match(text, pos)
            if match and match.end() > pos:
                self.emit(NUM, match.group(0), pos, match.end())
                return match.end()
        match = _NAME.match(text, pos)
        if match:
            self.emit(NAME, match.group(0), pos, match.end())
            return match.end()
        match = _PUNCT.match(text, pos)
        end = match.end() if match else pos + 1
        value = text[pos:end]
        if value in _OPENERS:
            self.depth += 1
        elif value in _CLOSERS and self.depth > 0:
            self.depth -= 1
        self.emit(PUNCT, value, pos, end)
        return end

    def _interpolating(self, pattern: re.Pattern[str], quote: str, plain: str, dynamic: str, pos: int) -> int:
        match = pattern.match(self.text, pos)
        end = match.end() if match else pos + 1
        raw = self.text[pos:end]
        body = raw[1:-1] if len(raw) > 1 and raw.endswith(quote) else raw[1:]
        names = _interpolated(body)
        if plain == dynamic:  # a backtick command is always a shell token
            self.emit(dynamic, body, pos, end, names)
        else:
            self.emit(dynamic if names else plain, body, pos, end, names)
        return end

    def _heredoc(self, pos: int) -> int | None:
        head = _HEREDOC.match(self.text, pos)
        if head is None:
            return None
        nowdoc = head.group(1) is not None
        label = head.group(2) or head.group(3) or head.group(4)
        body_start = head.end()
        closing = re.compile(rf"^[ \t]*{re.escape(label)}\b", re.M).search(self.text, body_start)
        body_end = closing.start() if closing else self.n
        end = closing.end() if closing else self.n
        body = self.text[body_start:body_end]
        names = () if nowdoc else _interpolated(body)
        self.emit(ISTR if names else STR, body, pos, end, names)
        return end


def tokenize(text: str) -> list[Token] | None:
    """Tokens of ``text``, or None when it exceeds the size, token or nesting bound."""
    return _Lexer(text).run()
