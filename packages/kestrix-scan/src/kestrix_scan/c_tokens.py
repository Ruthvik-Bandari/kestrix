# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""One bounded tokenizer for Go, Java, Kotlin and C# in pure Python. Source is read as text, never run.

It is not a parser. It produces the token stream the structural matcher in ``server_index.py`` needs, with the same
``Token`` as the PHP tokenizer:

- **Comments** (``//`` and ``/* */``; Kotlin's nest) are dropped.
- **Strings.** Plain literals are ``str`` tokens: Go ``"..."``, raw ```...``` and runes; Java and Kotlin ``"..."``
  and ``\"\"\"`` text blocks; C# ``"..."``, verbatim ``@"..."`` and raw ``\"\"\"`` literals; character literals in
  every language. Kotlin templates (``"$x"``, ``"${expr}"``) and C# interpolated strings (``$"{expr}"``, also
  ``$@"..."`` and ``$\"\"\"...\"\"\"``) that use a name are ``istr`` tokens whose ``vars`` are the names the
  expressions start with (``{user.Name}`` gives ``user``). An unterminated string ends at the end of its line
  (``"..."``) or of the file (raw and verbatim forms).
- **Names** (``[A-Za-z_]\\w*``, Unicode letters included); a C# ``@name`` and a Kotlin ```name``` are names.
  Annotations and attributes are ordinary ``@`` and ``[`` punctuation followed by names.
- ``<`` and ``>`` are always single tokens (``List<List<String>>`` closes twice), so shifts read as two operators.

Malformed input never raises. More than ``MAX_TOKENS`` tokens, more than ``MAX_NESTING`` open brackets, or text over
``MAX_CHARS`` give ``None`` (the file is reported as ``too_complex``). Every step advances and each pattern runs once
per position, so the work is linear in the file size.
"""

from __future__ import annotations

import bisect
import re

from .php_tokens import ISTR, NAME, NUM, PUNCT, STR, Token

MAX_TOKENS = 500_000
MAX_NESTING = 512
MAX_CHARS = 4_000_000
LANGUAGES = ("go", "java", "kotlin", "csharp")

_WS = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"[^\n\r]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.S)
_NAME = re.compile(r"[A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*")
_NUMBER = re.compile(r"0[xXbBoO][\da-fA-F_]+[lLuU]*|(?:\d[\d_]*(?:\.\d[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?[a-zA-Z]*")
_DOUBLE = re.compile(r'"(?:[^"\\\n\r]|\\[\s\S])*"?')
_CHAR = re.compile(r"'(?:[^'\\\n\r]|\\[^\n\r])*'?")
_GO_RAW = re.compile(r"`[^`]*`?")
_TRIPLE = re.compile(r'("{3,})[\s\S]*?(?:\1|\Z)')
_VERBATIM = re.compile(r'"(?:[^"]|"")*"?')
_BACKTICK_NAME = re.compile(r"`([^`\n\r]+)`")
_PUNCT = re.compile(
    r"\?\?=|\.\.\.|:=|::|->|=>|==|!=|<=|>=|&&|\|\||\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<-|\?\.|\?:|\?\?|!!|\.\."
    r"|[(){}\[\];,<>+\-*/%&|^!~?:=.@#\\$]"
)
_ROOT = re.compile(r"(?<![\w.$])[A-Za-z_][\w]*")
_OPENERS = frozenset("([{")
_CLOSERS = frozenset(")]}")


def _roots(expressions: list[str]) -> tuple[str, ...]:
    """The names the interpolated expressions start with (``user.Name`` gives ``user``), in order, unique."""
    names: list[str] = []
    for expr in expressions:
        for match in _ROOT.finditer(re.sub(r'"(?:[^"\\]|\\.)*"', '""', expr)):
            if match.group(0) not in names:
                names.append(match.group(0))
    return tuple(names)


def _braced(text: str, start: int, end: int, *, one_line: bool = False) -> int:
    """Offset after the ``}`` that closes the ``{`` at ``start - 1``, skipping nested braces and strings; ``end`` if none
    (or the line break, with ``one_line``)."""
    depth = 1
    k = start
    while k < end:
        char = text[k]
        if one_line and char in "\n\r":
            return k
        if char == '"':
            match = _DOUBLE.match(text, k)
            k = match.end() if match and match.end() > k else k + 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return end


def _kotlin_template(body: str) -> list[str]:
    """Expressions of ``$name`` and ``${expr}`` in a Kotlin string body (an escaped ``\\$`` does not count)."""
    out: list[str] = []
    k = 0
    n = len(body)
    while k < n:
        char = body[k]
        if char == "\\":
            k += 2
            continue
        if char == "$" and k + 1 < n:
            if body[k + 1] == "{":
                close = _braced(body, k + 2, n)
                out.append(body[k + 2 : close - 1])
                k = close
                continue
            match = _NAME.match(body, k + 1)
            if match:
                out.append(match.group(0))
                k = match.end()
                continue
        k += 1
    return out


def _csharp_holes(body: str, braces: int) -> list[str]:
    """Expressions of the ``{expr}`` holes of a C# interpolated string body. ``braces``: how many ``{`` open a hole
    (1, or the count of ``$`` of a raw interpolated literal); doubled braces of an ordinary one are text."""
    out: list[str] = []
    k = 0
    n = len(body)
    opener = "{" * braces
    while k < n:
        if braces == 1 and body.startswith("{{", k):
            k += 2
            continue
        if body.startswith(opener, k):
            close = _braced(body, k + braces, n)
            expr = body[k + braces : close - 1]
            depth = 0
            for idx, char in enumerate(expr):  # a format or alignment part (`{x:N2}`, `{x,10}`) is not code
                if char in "([":
                    depth += 1
                elif char in ")]":
                    depth -= 1
                elif char in ":," and depth == 0 and "?" not in expr[:idx]:
                    expr = expr[:idx]
                    break
            out.append(expr)
            k = close
            continue
        k += 1
    return out


def _line_template_end(text: str, start: int, hole: str) -> int:
    """Offset after the closing quote of a one-line string whose body starts at ``start`` and whose holes open with
    ``hole`` (Kotlin ``${``, C# ``{``), so a quote inside a hole does not end it. Unterminated: the line break."""
    n = len(text)
    k = start
    while k < n:
        char = text[k]
        if char in "\n\r":
            return k
        if char == "\\":
            k += 2
            continue
        if char == '"':
            return k + 1
        if text.startswith(hole, k):
            if hole == "{" and text.startswith("{{", k):
                k += 2
                continue
            k = _braced(text, k + len(hole), n, one_line=True)
            continue
        k += 1
    return n


class _Lexer:
    def __init__(self, text: str, language: str) -> None:
        self.text = text
        self.n = len(text)
        self.lang = language
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
        while pos < self.n:
            if len(self.tokens) > MAX_TOKENS or self.depth > MAX_NESTING:
                return None
            pos = self._step(pos)
        return self.tokens

    def _comment(self, pos: int) -> int | None:
        text = self.text
        if text.startswith("//", pos):
            match = _LINE_COMMENT.match(text, pos)
            return max(match.end() if match else pos, pos + 2)
        if not text.startswith("/*", pos):
            return None
        if self.lang != "kotlin":
            match = _BLOCK_COMMENT.match(text, pos)
            return match.end() if match else self.n
        depth = 0
        k = pos
        while k < self.n:  # Kotlin block comments nest
            if text.startswith("/*", k):
                depth += 1
                k += 2
            elif text.startswith("*/", k):
                depth -= 1
                k += 2
                if depth == 0:
                    return k
            else:
                k += 1
        return self.n

    def _step(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char.isspace():
            match = _WS.match(text, pos)
            return match.end() if match else pos + 1
        if char == "/":
            skipped = self._comment(pos)
            if skipped is not None:
                return skipped
        string = self._string(pos)
        if string is not None:
            return string
        if char.isdigit() or (char == "." and text[pos + 1 : pos + 2].isdigit()):
            match = _NUMBER.match(text, pos)
            if match and match.end() > pos:
                self.emit(NUM, match.group(0), pos, match.end())
                return match.end()
        if char == "@" and self.lang == "csharp" and _NAME.match(text, pos + 1):
            match = _NAME.match(text, pos + 1)
            assert match is not None
            self.emit(NAME, match.group(0), pos, match.end())
            return match.end()
        if char == "`" and self.lang == "kotlin":
            match = _BACKTICK_NAME.match(text, pos)
            if match:
                self.emit(NAME, match.group(1), pos, match.end())
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

    def _plain(self, pattern: re.Pattern[str], pos: int, open_len: int, close: str) -> int:
        match = pattern.match(self.text, pos)
        end = match.end() if match and match.end() > pos else pos + 1
        raw = self.text[pos:end]
        body = (
            raw[open_len : -len(close)] if len(raw) >= open_len + len(close) and raw.endswith(close) else raw[open_len:]
        )
        self.emit(STR, body, pos, end)
        return end

    def _string(self, pos: int) -> int | None:
        text = self.text
        char = text[pos]
        lang = self.lang
        if char == "'":
            return self._plain(_CHAR, pos, 1, "'")
        if lang == "go":
            if char == "`":
                return self._plain(_GO_RAW, pos, 1, "`")
            return self._plain(_DOUBLE, pos, 1, '"') if char == '"' else None
        if lang == "csharp":
            return self._csharp_string(pos)
        if char != '"':
            return None
        triple = text.startswith('"""', pos)
        match = _TRIPLE.match(text, pos) if triple else None
        if triple:
            end = match.end() if match and match.end() > pos else pos + 1
        elif lang == "kotlin":
            end = _line_template_end(text, pos + 1, "${")
        else:
            found = _DOUBLE.match(text, pos)
            end = found.end() if found and found.end() > pos else pos + 1
        quotes = len(match.group(1)) if match else 1
        raw = text[pos:end]
        body = raw[quotes:-quotes] if len(raw) >= 2 * quotes and raw.endswith('"' * quotes) else raw[quotes:]
        names = _roots(_kotlin_template(body)) if lang == "kotlin" else ()
        self.emit(ISTR if names else STR, body, pos, end, names)
        return end

    def _csharp_string(self, pos: int) -> int | None:
        text = self.text
        k = pos
        dollars = 0
        verbatim = False
        while k < self.n and k - pos < 8 and text[k] in "$@":
            if text[k] == "$":
                dollars += 1
            else:
                verbatim = True
            k += 1
        if k >= self.n or text[k] != '"':
            return None
        if text.startswith('"""', k):
            match = _TRIPLE.match(text, k)
            end = match.end() if match and match.end() > k else k + 1
            quotes = len(match.group(1)) if match else 3
            raw = text[k:end]
            body = raw[quotes:-quotes] if len(raw) >= 2 * quotes and raw.endswith('"' * quotes) else raw[quotes:]
        elif verbatim:
            match = _VERBATIM.match(text, k)
            end = match.end() if match and match.end() > k else k + 1
            body = text[k + 1 : end - 1] if end - k > 1 and text[end - 1] == '"' else text[k + 1 : end]
        else:
            found = _DOUBLE.match(text, k)
            end = _line_template_end(text, k + 1, "{") if dollars else (found.end() if found else k + 1)
            body = text[k + 1 : end - 1] if end - k > 1 and text[end - 1] == '"' else text[k + 1 : end]
        names = _roots(_csharp_holes(body, dollars)) if dollars else ()
        self.emit(ISTR if names else STR, body, pos, end, names)
        return end


def tokenize(text: str, language: str) -> list[Token] | None:
    """Tokens of ``text`` in ``language`` (go, java, kotlin or csharp), or None when a bound is exceeded."""
    return _Lexer(text, language).run()
