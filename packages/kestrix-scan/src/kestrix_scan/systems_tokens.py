# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The bounded C-family tokenizer of ``c_tokens.py``, extended to C and C++, Rust and Swift. Source is read as text, never run.

It is the same lexer (same ``Token``, the same bounds, linear work) with these languages' comments and literals:

- **C and C++.** ``"..."`` and ``'...'`` with the ``u8``, ``u``, ``U`` and ``L`` prefixes, and C++ raw strings
  ``R"delim(...)delim"``. Preprocessor lines are ordinary tokens (``#``, ``include``, ``<`` ...).
- **Rust.** Block comments nest. ``"..."`` may span lines; byte, C and raw strings (``b"..."``, ``c"..."``,
  ``r#"..."#``, ``br"..."``) are plain strings; ``'x'`` and ``b'x'`` are character literals, and a lifetime (``'a``)
  is the punctuation ``'`` followed by a name.
- **Swift.** Block comments nest. ``"..."``, multi-line ``\"\"\"...\"\"\"`` and raw ``#"..."#`` strings; a string with an
  interpolation (``\\(expr)``, or ``\\#(expr)`` in a raw string) that uses a name is an ``istr`` token whose ``vars`` are
  the names the expressions start with. ``#if``, ``#selector`` and the like are ``#`` followed by a name.

Malformed input never raises; an unterminated string ends at the end of its line (C) or of the file (the others).
"""

from __future__ import annotations

import re

from .c_tokens import _DOUBLE, MAX_CHARS, MAX_NESTING, MAX_TOKENS, _Lexer, _roots
from .php_tokens import ISTR, PUNCT, STR, Token

LANGUAGES = ("c", "rust", "swift")
__all__ = ["LANGUAGES", "MAX_CHARS", "MAX_NESTING", "MAX_TOKENS", "tokenize"]

_C_PREFIXED = re.compile(r"(?:u8|[uUL])(?=[\"'])|(?:u8|[uUL])?R(?=\")")
_C_RAW_OPEN = re.compile(r'"([^()\\\s"]{0,16})\(')
_C_CHAR = re.compile(r"'(?:[^'\\\n\r]|\\[^\n\r])*'?")
_RUST_PREFIX = re.compile(r"(?:b|c)?r(#*)\"|[bc]\"|b'")
_RUST_STRING = re.compile(r'"(?:[^"\\]|\\[\s\S])*"?')
_RUST_CHAR = re.compile(r"'(?:[^'\\\n\r]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|[^\n\r]))'")
_SWIFT_OPEN = re.compile(r'(#*)("""|")')


def _swift_end(text: str, start: int, hashes: int, triple: bool) -> tuple[int, list[str]]:
    """(offset after the closing delimiter, interpolated expressions) of a Swift string whose body starts at ``start``.
    An interpolation's parentheses may hold nested strings; the end of the file (or of the line, for ``"..."``) ends it."""
    close = ('"""' if triple else '"') + "#" * hashes
    escape = "\\" + "#" * hashes
    n = len(text)
    k = start
    holes: list[str] = []
    while k < n:
        char = text[k]
        if char in "\n\r" and not triple:
            return k, holes
        if text.startswith(escape, k):
            after = k + len(escape)
            if after < n and text[after] == "(":
                depth = 1
                j = after + 1
                while j < n and depth:
                    c = text[j]
                    if c == '"':
                        match = _DOUBLE.match(text, j)
                        j = match.end() if match and match.end() > j else j + 1
                        continue
                    if c in "\n\r" and not triple:
                        break
                    depth += 1 if c == "(" else -1 if c == ")" else 0
                    j += 1
                holes.append(text[after + 1 : j - 1] if depth == 0 else text[after + 1 : j])
                k = j
                continue
            k = after + 1
            continue
        if text.startswith(close, k):
            return k + len(close), holes
        k += 1
    return n, holes


class _SystemsLexer(_Lexer):
    def _comment(self, pos: int) -> int | None:
        if self.lang == "c" or not self.text.startswith("/*", pos):
            return super()._comment(pos)
        text = self.text
        depth = 0
        k = pos
        while k < self.n:  # Rust and Swift block comments nest
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

    def _string(self, pos: int) -> int | None:
        if self.lang == "c":
            return self._c_string(pos)
        if self.lang == "rust":
            return self._rust_string(pos)
        return self._swift_string(pos)

    def _emit_str(self, start: int, end: int, body: str) -> int:
        self.emit(STR, body, start, end)
        return end

    def _c_string(self, pos: int) -> int | None:
        text = self.text
        char = text[pos]
        k = pos
        if char in "uULR":
            prefix = _C_PREFIXED.match(text, pos)
            if prefix is None:
                return None
            k = prefix.end()
            if text[k - 1] == "R":
                raw = _C_RAW_OPEN.match(text, k)
                if raw is None:
                    return None
                closing = ")" + raw.group(1) + '"'
                found = text.find(closing, raw.end())
                end = found + len(closing) if found >= 0 else self.n
                return self._emit_str(pos, end, text[raw.end() : found if found >= 0 else self.n])
            char = text[k]
        if char == '"':
            match = _DOUBLE.match(text, k)
            end = match.end() if match and match.end() > k else k + 1
        elif char == "'":
            match = _C_CHAR.match(text, k)
            end = match.end() if match and match.end() > k else k + 1
        else:
            return None
        raw_text = text[k + 1 : end]
        return self._emit_str(pos, end, raw_text[:-1] if raw_text.endswith(text[k]) else raw_text)

    def _rust_string(self, pos: int) -> int | None:
        text = self.text
        char = text[pos]
        if char == "'":
            match = _RUST_CHAR.match(text, pos)
            if match is None:  # a lifetime or a loop label: the quote, then the name as usual
                self.emit(PUNCT, "'", pos, pos + 1)
                return pos + 1
            return self._emit_str(pos, match.end(), match.group(0)[1:-1])
        if char in "bcr":
            prefix = _RUST_PREFIX.match(text, pos)
            if prefix is None:
                return None
            if prefix.group(0).endswith("'"):
                match = _RUST_CHAR.match(text, prefix.end() - 1)
                if match is None:
                    return None
                return self._emit_str(pos, match.end(), match.group(0)[1:-1])
            if prefix.group(1) is not None:  # raw: no escapes, closed by a quote and as many hashes
                closing = '"' + prefix.group(1)
                found = text.find(closing, prefix.end())
                end = found + len(closing) if found >= 0 else self.n
                return self._emit_str(pos, end, text[prefix.end() : found if found >= 0 else self.n])
            pos_quote = prefix.end() - 1
        elif char == '"':
            pos_quote = pos
        else:
            return None
        match = _RUST_STRING.match(text, pos_quote)
        end = match.end() if match and match.end() > pos_quote else pos_quote + 1
        body = text[pos_quote + 1 : end]
        return self._emit_str(pos, end, body[:-1] if body.endswith('"') and end - pos_quote > 1 else body)

    def _swift_string(self, pos: int) -> int | None:
        text = self.text
        if text[pos] not in '#"':
            return None
        match = _SWIFT_OPEN.match(text, pos)
        if match is None:
            return None
        hashes = len(match.group(1))
        triple = match.group(2) == '"""'
        end, holes = _swift_end(text, match.end(), hashes, triple)
        close_len = (3 if triple else 1) + hashes
        closing = ('"""' if triple else '"') + "#" * hashes
        body = (
            text[match.end() : end - close_len]
            if text.startswith(closing, end - close_len)
            else text[match.end() : end]
        )
        names = _roots(holes)
        self.emit(ISTR if names else STR, body, pos, max(end, pos + 1), names)
        return max(end, pos + 1)


def tokenize(text: str, language: str) -> list[Token] | None:
    """Tokens of ``text`` in ``language`` (c for C and C++, rust or swift), or None when a bound is exceeded."""
    return _SystemsLexer(text, language).run()
