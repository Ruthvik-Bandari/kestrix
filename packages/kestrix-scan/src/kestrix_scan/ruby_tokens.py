# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A bounded Ruby tokenizer in pure Python. Source is read as text, never run.

It is not a parser. It produces the token stream the structural matcher in ``server_index.py`` needs, with the same
``Token`` as the PHP tokenizer:

- **Comments** (``#`` to the end of the line, ``=begin`` ... ``=end``) are dropped; ``__END__`` at the start of a line
  ends the code.
- **Strings.** ``'...'``, ``%q(...)``, ``%w[...]``, ``%i[...]``, symbols (``:name``, ``:"..."``) and heredocs with a
  quoted label are plain ``str`` tokens. ``"..."``, ``%Q(...)``, ``%(...)``, ``%W[...]``, regular expressions
  (``/.../``, ``%r{...}``) and heredocs (``<<~SQL``, ``<<-EOS``, ``<<EOS``) whose ``#{...}`` use a name are ``istr``
  tokens; their ``vars`` are the names the interpolated expressions start with (``#{params[:id]}`` gives
  ``params``). Backticks and ``%x(...)`` are ``shell`` tokens. A heredoc's token sits where its label is written and
  its body lines are skipped when the lexer reaches them. Unterminated literals end at the end of the file.
- **Regular expression or division** is decided by the previous token: after an operator, an opening bracket, a
  keyword such as ``if`` or ``when``, or at the start, ``/`` begins a regular expression; after a name followed by a
  space with no space after the ``/`` (``split /,/``) too; otherwise it divides. ``%`` literals follow the same rule.
- **Names** include ``@instance``, ``@@class`` and ``$global`` variables and a trailing ``?`` or ``!``.

Malformed input never raises. More than ``MAX_TOKENS`` tokens, ``MAX_NESTING`` open brackets, ``MAX_HEREDOCS``
heredocs or text over ``MAX_CHARS`` give ``None`` (the file is reported as ``too_complex``).
"""

from __future__ import annotations

import bisect
import re

from .php_tokens import ISTR, NAME, NUM, PUNCT, SHELL, STR, Token

MAX_TOKENS = 500_000
MAX_NESTING = 512
MAX_CHARS = 4_000_000
MAX_HEREDOCS = 2_000

_BLANK = re.compile(r"[ \t\f\v]+|\\\r?\n")
_COMMENT = re.compile(r"#[^\n\r]*")
_EMBEDDED_DOC = re.compile(r"=begin\b.*?(?:^=end\b[^\n]*|\Z)", re.S | re.M)
_NAME = re.compile(r"(?:@@|@|\$)?[A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*(?:[?!](?![=~]))?")
_GLOBAL_SPECIAL = re.compile(r"\$[!@&`'+~=/\\,;.<>_*$?:\"0-9]")
_NUMBER = re.compile(r"0[xXbBoOdD][\da-fA-F_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?r?i?")
_SINGLE = re.compile(r"'(?:[^'\\]|\\[\s\S])*'?")
_SYMBOL = re.compile(
    r":(?:[A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*[?!=]?|\[\]=?|<=>|===?|=~|!=|<<|>>|[+\-*/%<>!~^&|])"
)
_HEREDOC = re.compile(r"<<([~-]?)(?:(['\"`])([A-Za-z_]\w*)\2|([A-Za-z_]\w*))")
_PERCENT = re.compile(r"%([qQwWiIxrs]?)([^\w\s])")
_PUNCT = re.compile(
    r"\*\*=|<=>|===|\.\.\.|\|\|=|&&=|<<=|>>=|::|->|=>|==|!=|=~|!~|>=|<=|&&|\|\||<<|>>|\+=|-=|\*=|/=|%=|\|=|&=|\^="
    r"|\*\*|&\.|\.\.|[(){}\[\];,<>+\-*/%&|^!~?:=.@$\\`]"
)
_ROOT = re.compile(r"(?<![\w.:@$])(?:@@|@|\$)?[A-Za-z_]\w*[?!]?")
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}
_OPENERS = frozenset("([{")
_CLOSERS = frozenset(")]}")
_VALUE_KEYWORDS = frozenset({"self", "nil", "true", "false", "end", "__FILE__", "__LINE__", "__method__"})
_OPERAND_KEYWORDS = frozenset(
    {"if", "elsif", "unless", "while", "until", "when", "and", "or", "not", "return", "then", "do", "else", "in"}
    | {"case", "puts", "print", "raise", "yield", "begin", "p"}
)


def _roots(expressions: list[str]) -> tuple[str, ...]:
    names: list[str] = []
    for expr in expressions:
        for match in _ROOT.finditer(re.sub(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|:\w+", '""', expr)):
            if match.group(0) not in names:
                names.append(match.group(0))
    return tuple(names)


def _skip_braced(text: str, start: int, end: int) -> int:
    """Offset after the ``}`` closing the ``#{`` before ``start`` (nested braces and quoted strings skipped)."""
    depth = 1
    k = start
    while k < end:
        char = text[k]
        if char in "\"'":
            close = text.find(char, k + 1, end)
            while close > 0 and text[close - 1] == "\\":
                close = text.find(char, close + 1, end)
            k = close + 1 if close > 0 else end
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return end


def _scan_body(text: str, start: int, close: str, opener: str | None, interpolate: bool) -> tuple[int, list[str]]:
    """(offset after the closing delimiter, interpolated expressions) of a literal body starting at ``start``."""
    n = len(text)
    exprs: list[str] = []
    depth = 0
    k = start
    while k < n:
        char = text[k]
        if char == "\\":
            k += 2
            continue
        if interpolate and char == "#" and text.startswith("#{", k):
            end = _skip_braced(text, k + 2, n)
            exprs.append(text[k + 2 : end - 1])
            k = end
            continue
        if opener is not None and char == opener:
            depth += 1
        elif char == close:
            if depth == 0:
                return k + 1, exprs
            depth -= 1
        k += 1
    return n, exprs


class _Lexer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.tokens: list[Token] = []
        self.line_starts = [0, *(m.end() for m in re.finditer(r"\r\n|\r|\n", text))]
        self.depth = 0
        self.resume: int | None = None  # where code continues after the heredoc bodies of the current line
        self.heredocs = 0
        self.space_before = False

    def _line(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def emit(self, kind: str, value: str, start: int, end: int, names: tuple[str, ...] = ()) -> None:
        line = self._line(start)
        self.tokens.append(
            Token(kind, value, line, start - self.line_starts[line - 1] + 1, self._line(max(start, end - 1)), names)
        )

    def _line_start(self, pos: int) -> bool:
        return pos == 0 or self.text[pos - 1] in "\n\r"

    def _operand_expected(self, pos: int) -> bool:
        if not self.tokens:
            return True
        prev = self.tokens[-1]
        if prev.end_line < self._line(pos) and not (prev.kind == PUNCT and prev.value in (".", "&.")):
            return True  # a new line starts a new expression unless the last one ends in an operator
        if prev.kind == PUNCT:
            return prev.value not in (")", "]", "}")
        if prev.kind == NAME:
            if prev.value in _OPERAND_KEYWORDS:
                return True
            if prev.value in _VALUE_KEYWORDS or prev.value[:1].isupper():
                return False
            return self.space_before
        return False

    def run(self) -> list[Token] | None:
        if self.n > MAX_CHARS:
            return None
        pos = 0
        while pos < self.n:
            if len(self.tokens) > MAX_TOKENS or self.depth > MAX_NESTING or self.heredocs > MAX_HEREDOCS:
                return None
            pos = self._step(pos)
        return self.tokens

    def _step(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char in "\n\r":
            self.space_before = True
            if self.resume is not None:
                resume, self.resume = self.resume, None
                return max(resume, pos + 1)
            return pos + 1
        match = _BLANK.match(text, pos)
        if match:
            self.space_before = True
            return match.end()
        if self._line_start(pos):
            if text.startswith("=begin", pos):
                found = _EMBEDDED_DOC.match(text, pos)
                return found.end() if found else self.n
            if text.startswith("__END__", pos) and text[pos + 7 : pos + 8] in ("", "\n", "\r"):
                return self.n
        end = self._literal(pos)
        self.space_before = False
        return end

    def _literal(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char == "#":
            match = _COMMENT.match(text, pos)
            return match.end() if match else pos + 1
        if char == "'":
            match = _SINGLE.match(text, pos)
            end = match.end() if match and match.end() > pos else pos + 1
            self.emit(
                STR,
                text[pos + 1 : end - 1] if end - pos > 1 and text[end - 1] == "'" else text[pos + 1 : end],
                pos,
                end,
            )
            return end
        if char in '"`':
            return self._quoted(pos, pos + 1, char, None, interpolate=True, kind=SHELL if char == "`" else ISTR)
        if char == ":" and not text.startswith("::", pos) and (self._operand_expected(pos) or self.space_before):
            if text.startswith(':"', pos):
                return self._quoted(pos, pos + 2, '"', None, interpolate=True, kind=ISTR)
            match = _SYMBOL.match(text, pos)
            if match and (match.group(0)[1:2].isalpha() or match.group(0)[1:2] == "_" or self._operand_expected(pos)):
                self.emit(STR, match.group(0)[1:], pos, match.end())
                return match.end()
        if char == "<" and text.startswith("<<", pos):
            heredoc = self._heredoc(pos)
            if heredoc is not None:
                return heredoc
        if char == "/" and self._operand_expected(pos) and text[pos + 1 : pos + 2] not in (" ", "="):
            return self._quoted(pos, pos + 1, "/", None, interpolate=True, kind=ISTR)
        if char == "%" and self._operand_expected(pos):
            match = _PERCENT.match(text, pos)
            if match and not (match.group(1) == "" and match.group(2) in "=;,)"):
                return self._percent(pos, match)
        if char.isdigit():
            match = _NUMBER.match(text, pos)
            if match and match.end() > pos:
                self.emit(NUM, match.group(0), pos, match.end())
                return match.end()
        if char == "$":
            match = _GLOBAL_SPECIAL.match(text, pos)
            if match and not _NAME.match(text, pos):
                self.emit(NAME, match.group(0), pos, match.end())
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

    def _quoted(self, pos: int, body: int, close: str, opener: str | None, *, interpolate: bool, kind: str) -> int:
        end, exprs = _scan_body(self.text, body, close, opener, interpolate)
        closed = end > body and self.text[end - 1] == close
        value = self.text[body : end - 1 if closed else end]
        if close == "/":  # regex flags
            while end < self.n and self.text[end] in "imxounse":
                end += 1
        names = _roots(exprs)
        if kind == SHELL:
            self.emit(SHELL, value, pos, end, names)
        else:
            self.emit(kind if names else STR, value, pos, end, names)
        return end

    def _percent(self, pos: int, match: re.Match[str]) -> int:
        letter, delim = match.group(1), match.group(2)
        close = _PAIRS.get(delim, delim)
        opener = delim if delim in _PAIRS else None
        interpolate = letter in ("", "Q", "W", "I", "x", "r")
        kind = SHELL if letter == "x" else ISTR
        end = self._quoted(pos, match.end(), close, opener, interpolate=interpolate, kind=kind)
        if letter == "r":
            while end < self.n and self.text[end] in "imxounse":
                end += 1
        return end

    def _heredoc(self, pos: int) -> int | None:
        text = self.text
        match = _HEREDOC.match(text, pos)
        if match is None:
            return None
        flag, quote, quoted_label, bare = match.groups()
        label = quoted_label or bare
        if not flag and not quote and not (label.isupper() and self._operand_expected(pos)):
            return None  # `x <<y` is a shift or an append
        self.heredocs += 1
        if self.resume is not None:
            body_start = self.resume
        else:
            newline = re.compile(r"\r\n|\r|\n").search(text, match.end())
            body_start = newline.end() if newline else self.n
        indent = r"[ \t]*" if flag else ""
        closing = re.compile(rf"^{indent}{re.escape(label)}[ \t]*(?:\r\n|\r|\n|\Z)", re.M).search(text, body_start)
        body_end = closing.start() if closing else self.n
        self.resume = closing.end() if closing else self.n
        body = text[body_start:body_end]
        if quote == "'":
            self.emit(STR, body, pos, match.end())
        else:
            _, exprs = _scan_body(body + "\x00", 0, "\x00", None, True)
            names = _roots(exprs)
            kind = SHELL if quote == "`" else (ISTR if names else STR)
            self.emit(kind, body, pos, match.end(), names)
        return match.end()


def tokenize(text: str) -> list[Token] | None:
    """Tokens of Ruby ``text``, or None when it exceeds a bound."""
    return _Lexer(text).run()
