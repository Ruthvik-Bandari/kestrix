# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A bounded JavaScript and TypeScript tokenizer in pure Python. Source is read as text, never run.

It is not a parser. It produces the token stream the structural matcher in ``js_index.py`` needs:

- **Strings** in ``'`` and ``"``, with escapes; one that is not closed ends at the line break.
- **Template literals** as ``tpl`` (no substitution) or ``tpl_head``, ``tpl_mid`` ... ``tpl_tail`` around the
  tokens of each ``${...}``, which may nest templates of their own.
- **Comments** (``//``, ``/* */`` and a ``#!`` first line) are dropped.
- **Regular expression literals versus division**, decided by the previous significant token: after an
  operator, an opening bracket, ``}``, a keyword such as ``return`` or ``typeof``, or at the start, ``/``
  begins a regex; after a name, a number, a string, ``)`` or ``]`` it divides. A regex that does not
  close on its line is read as a division sign instead.
- **JSX**, in ``.js``/``.jsx``/``.tsx`` style files: ``<`` where an expression may start, followed by a tag
  name or ``>``, opens an element. Tag and attribute names become ``jsx``/``jsx_attr`` tokens, text
  between tags is dropped, and ``{...}`` containers are tokenized as code. In ``.tsx``, ``<T,>`` and
  ``<T extends ...>`` stay generic type parameters.
- **TypeScript** needs no special mode: annotations, generics and ``as`` casts are ordinary tokens that the
  rules step over.

Malformed input never raises: unterminated strings, templates, comments and elements end at the line or the
end of the file. More than ``MAX_TOKENS`` tokens or ``MAX_NESTING`` open braces, templates and elements
give ``None`` (the file is reported as ``too_complex``).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

MAX_TOKENS = 500_000
MAX_NESTING = 512

NAME, NUM, STR, TPL, TPL_HEAD, TPL_MID, TPL_TAIL, REGEX, PUNCT, JSX, JSX_ATTR = (
    "name",
    "num",
    "str",
    "tpl",
    "tpl_head",
    "tpl_mid",
    "tpl_tail",
    "regex",
    "punct",
    "jsx",
    "jsx_attr",
)


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # one of the constants above
    value: str  # the name, the operator, or a string's or template chunk's text without quotes
    start: int  # offset of the first character
    end: int  # offset after the last character
    line: int  # 1-based line of ``start``
    col: int  # 1-based column of ``start``
    end_line: int  # 1-based line of the last character


_WS = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"[^\n\r\u2028\u2029]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.S)
_IDENT = re.compile(r"#?(?:[^\W\d]|\$)[\w$]*")
_NUMBER = re.compile(r"(?:0[xXoObB][\da-fA-F_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?)n?")
_STRINGS = {
    "'": re.compile(r"'(?:[^'\\\n\r]|\\(?:\r\n|[\s\S]))*'?"),
    '"': re.compile(r'"(?:[^"\\\n\r]|\\(?:\r\n|[\s\S]))*"?'),
}
_TEMPLATE_BODY = re.compile(r"(?:[^`\\$]|\\[\s\S]|\$(?!\{))*")
_REGEX = re.compile(r"/(?:[^/\\\[\n\r]|\\[^\n\r]|\[(?:[^\]\\\n\r]|\\[^\n\r])*\])+/[A-Za-z]*")
_PUNCT = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.(?!\d)"
    r"|\+\+|--|\+=|-=|\*=|%=|&=|\|=|\^=|<<|>>|\*\*|[(){}\[\];,<>+\-*%&|^!~?:=.@#\\]"
)
_ESCAPE = re.compile(r"\\(?:\r\n|[\s\S])")
_JSX_TAG = re.compile(r"\s*([^\W\d][\w$.:-]*|\$[\w$.:-]*)")
_JSX_GENERIC = re.compile(r"\s*(?:,|extends\b)")  # <T,> and <T extends U>; TypeScript reads <T>(x) as JSX in .tsx
_JSX_ATTR = re.compile(r"[^\s=/>{}'\"<]+")
_JSX_TEXT = re.compile(r"[^<{]+")
_JSX_STRINGS = {"'": re.compile(r"'[^']*'?"), '"': re.compile(r'"[^"]*"?')}
_JSX_CLOSE = re.compile(r"<\s*/[^>]*>?")

# Keywords after which an expression (so a regex or a JSX element) may start.
_EXPR_KEYWORDS = frozenset(
    {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else"}
    | {"yield", "await", "extends"}
)
_OPERAND_END = frozenset({")", "]", "++", "--"})

# Mode stack entries. The code frames end at their ``}``; the JSX frames are lexed by their own methods.
_CODE, _BRACE, _TPL_EXPR, _JSX_ATTR_EXPR, _JSX_CHILD_EXPR, _JSX_TAG_MODE, _JSX_CHILDREN = range(7)


def _end(regex: re.Pattern[str], text: str, pos: int) -> int:
    """Where ``regex`` stops matching at ``pos``; at least one character on, so the lexer always advances."""
    match = regex.match(text, pos)
    return max(match.end(), pos + 1) if match else pos + 1


def _unescape(body: str) -> str:
    return _ESCAPE.sub(lambda m: m.group(0)[1:], body)


class _Lexer:
    def __init__(self, text: str, jsx: bool, generics_in_jsx: bool) -> None:
        self.text = text
        self.n = len(text)
        self.jsx = jsx
        self.generics_in_jsx = generics_in_jsx  # .tsx: <T,> and <T extends X> are type parameters
        self.tokens: list[Token] = []
        self.stack: list[int] = [_CODE]
        self.line_starts = [0, *(m.end() for m in re.finditer(r"\r\n|\r|\n", text))]

    # ----- emitting

    def _line(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def emit(self, kind: str, value: str, start: int, end: int) -> None:
        line = self._line(start)
        end_line = self._line(max(start, end - 1))
        self.tokens.append(Token(kind, value, start, end, line, start - self.line_starts[line - 1] + 1, end_line))

    def _expression_may_start(self) -> bool:
        if not self.tokens:
            return True
        prev = self.tokens[-1]
        if prev.kind == NAME:
            before = self.tokens[-2] if len(self.tokens) > 1 else None
            after_dot = before is not None and before.kind == PUNCT and before.value in (".", "?.")
            return prev.value in _EXPR_KEYWORDS and not after_dot
        if prev.kind == PUNCT:
            return prev.value not in _OPERAND_END
        return prev.kind in (TPL_HEAD, TPL_MID)

    # ----- driver

    def run(self) -> list[Token] | None:
        pos = 0
        if self.text.startswith("#!"):
            pos = _end(_LINE_COMMENT, self.text, 0)
        while pos < self.n:
            if len(self.tokens) > MAX_TOKENS or len(self.stack) > MAX_NESTING:
                return None
            mode = self.stack[-1]
            if mode == _JSX_TAG_MODE:
                pos = self._jsx_tag(pos)
            elif mode == _JSX_CHILDREN:
                pos = self._jsx_children(pos)
            else:
                pos = self._code(pos)
        return self.tokens

    # ----- code

    def _code(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char.isspace():
            return _end(_WS, text, pos)
        if char == "/":
            nxt = text[pos + 1 : pos + 2]
            if nxt == "/":
                return _end(_LINE_COMMENT, text, pos)
            if nxt == "*":
                return _end(_BLOCK_COMMENT, text, pos)
            if self._expression_may_start() and (match := _REGEX.match(text, pos)):
                self.emit(REGEX, match.group(0), pos, match.end())
                return match.end()
            op = "/=" if nxt == "=" else "/"
            self.emit(PUNCT, op, pos, pos + len(op))
            return pos + len(op)
        if char in _STRINGS:
            raw = text[pos : _end(_STRINGS[char], text, pos)]
            body = raw[1:-1] if len(raw) > 1 and raw.endswith(char) else raw[1:]
            self.emit(STR, _unescape(body), pos, pos + len(raw))
            return pos + len(raw)
        if char == "`":
            return self._template(pos, pos + 1, first=True)
        if char == "<":
            if text.startswith("<!--", pos):
                return _end(_LINE_COMMENT, text, pos)
            if self.jsx and self._expression_may_start():
                opened = self._jsx_open(pos)
                if opened is not None:
                    return opened
        if char == "{":
            self.emit(PUNCT, "{", pos, pos + 1)
            self.stack.append(_BRACE)
            return pos + 1
        if char == "}":
            return self._close_brace(pos)
        if char.isdigit() or (char == "." and text[pos + 1 : pos + 2].isdigit()):
            match = _NUMBER.match(text, pos)
            if match and match.end() > pos:
                self.emit(NUM, match.group(0), pos, match.end())
                return match.end()
        match = _IDENT.match(text, pos)
        if match:
            self.emit(NAME, match.group(0), pos, match.end())
            return match.end()
        match = _PUNCT.match(text, pos)
        end = match.end() if match else pos + 1
        self.emit(PUNCT, text[pos:end], pos, end)
        return end

    def _close_brace(self, pos: int) -> int:
        mode = self.stack[-1]
        if mode == _TPL_EXPR:
            self.stack.pop()
            return self._template(pos, pos + 1, first=False)
        self.emit(PUNCT, "}", pos, pos + 1)
        if mode in (_BRACE, _JSX_ATTR_EXPR, _JSX_CHILD_EXPR):
            self.stack.pop()
        return pos + 1

    def _template(self, start: int, body_start: int, *, first: bool) -> int:
        match = _TEMPLATE_BODY.match(self.text, body_start)  # may be empty: `` or `${
        body_end = match.end() if match else body_start
        body = _unescape(self.text[body_start:body_end])
        if self.text.startswith("${", body_end):
            self.emit(TPL_HEAD if first else TPL_MID, body, start, body_end + 2)
            self.stack.append(_TPL_EXPR)
            return body_end + 2
        end = min(body_end + 1, self.n)  # the closing backtick, or the end of an unterminated template
        self.emit(TPL if first else TPL_TAIL, body, start, end)
        return end

    # ----- JSX

    def _jsx_open(self, pos: int) -> int | None:
        """Lex ``<tag`` or ``<>`` at ``pos`` and enter the element, or return None when it is not JSX."""
        text = self.text
        after = pos + 1
        rest = _WS.match(text, after)
        probe = rest.end() if rest else after
        if text.startswith(">", probe):  # a fragment
            self.emit(JSX, "<>", pos, probe + 1)
            self.stack.append(_JSX_CHILDREN)
            return probe + 1
        match = _JSX_TAG.match(text, after)
        if match is None:
            return None
        if self.generics_in_jsx and _JSX_GENERIC.match(text, match.end()):
            return None
        self.emit(JSX, match.group(1), match.start(1), match.end(1))
        self.stack.append(_JSX_TAG_MODE)
        return match.end()

    def _element_closed(self, pos: int, end: int) -> None:
        self.stack.pop()
        if self.stack[-1] not in (_JSX_TAG_MODE, _JSX_CHILDREN):
            self.emit(JSX, "/>", pos, end)  # an operand in the surrounding code, like a closing parenthesis

    def _jsx_tag(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char.isspace():
            return _end(_WS, text, pos)
        if text.startswith("/>", pos):
            self._element_closed(pos, pos + 2)
            return pos + 2
        if char == ">":
            self.stack[-1] = _JSX_CHILDREN
            return pos + 1
        if char == "{":
            self.emit(PUNCT, "{", pos, pos + 1)
            self.stack.append(_JSX_ATTR_EXPR)
            return pos + 1
        if char in _JSX_STRINGS:
            raw = text[pos : _end(_JSX_STRINGS[char], text, pos)]
            body = raw[1:-1] if len(raw) > 1 and raw.endswith(char) else raw[1:]
            self.emit(STR, body, pos, pos + len(raw))
            return pos + len(raw)
        if char == "=":
            self.emit(PUNCT, "=", pos, pos + 1)
            return pos + 1
        if text.startswith("/*", pos):
            return _end(_BLOCK_COMMENT, text, pos)
        match = _JSX_ATTR.match(text, pos)
        if match:
            self.emit(JSX_ATTR, match.group(0), pos, match.end())
            return match.end()
        return pos + 1  # a stray character such as '/' or '<' inside a tag

    def _jsx_children(self, pos: int) -> int:
        text = self.text
        char = text[pos]
        if char == "{":
            self.emit(PUNCT, "{", pos, pos + 1)
            self.stack.append(_JSX_CHILD_EXPR)
            return pos + 1
        if char == "<":
            closing = _JSX_CLOSE.match(text, pos)
            if closing:
                self._element_closed(pos, closing.end())
                return closing.end()
            opened = self._jsx_open(pos)
            return opened if opened is not None else pos + 1
        return _end(_JSX_TEXT, text, pos)


def tokenize(text: str, *, jsx: bool = True, tsx: bool = False) -> list[Token] | None:
    """Tokens of ``text``, or None when it exceeds the token or nesting bound.

    ``jsx``: recognize JSX elements (off for ``.ts``, where ``<T>x`` is a type assertion). ``tsx``: in JSX,
    read ``<T,>`` and ``<T extends U>`` as type parameters.
    """
    return _Lexer(text, jsx, tsx).run()
