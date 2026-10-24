# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A bounded, safe reader for the block-style YAML that CI and Kubernetes files use. Nothing is run or expanded.

This is not a YAML parser. It reads the shapes GitHub Actions workflows and Kubernetes manifests are written in
and gives every node its 1-based source line, so a rule can point at the line:

- block mappings and block sequences (including a sequence at the same indent as its key, and ``- key: value``);
- plain, single-quoted and double-quoted scalars, with a plain or quoted scalar continued on the next lines;
- ``|`` and ``>`` block scalars (kept as their raw text: the node's line is the first content line);
- flow sequences and flow mappings written on one or several lines;
- comments, several documents separated by ``---`` and anchors or tags (dropped).

Aliases (``*name``) stay plain scalars, merge keys (``<<``) stay ordinary keys, and every scalar stays a string, so
``on`` is the key ``on`` and ``true`` is the text ``true``. Complex keys (``? key``) and tabs for indentation are not
supported. Bounds: line length, line count, nesting depth and node count; a file over a bound raises ``YamlError``
with the skip reason, and malformed input is read as leniently as the shapes above allow rather than rejected.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from .models import SkipReason

MAX_LINES = 30_000
MAX_LINE_CHARS = 8_192
MAX_DEPTH = 40
MAX_NODES = 200_000
MAX_DOCUMENTS = 2_000
MAX_JOINED_LINES = 200  # continuation lines read for one flow collection or quoted scalar


class YamlError(Exception):
    def __init__(self, reason: SkipReason) -> None:
        super().__init__(reason)
        self.reason: SkipReason = reason


@dataclass(slots=True)
class Scalar:
    value: str
    line: int
    quoted: bool = False
    block: bool = (
        False  # a ``|`` or ``>`` block: ``line`` is the first content line, content lines follow 1:1 for ``|``
    )


@dataclass(slots=True)
class Seq:
    items: list[Node]
    line: int


@dataclass(slots=True)
class Map:
    entries: list[tuple[str, int, Node]]  # (key, line of the key, value)
    line: int

    def get(self, key: str) -> Node | None:
        for name, _, value in self.entries:
            if name == key:
                return value
        return None

    def key_line(self, key: str) -> int:
        for name, line, _ in self.entries:
            if name == key:
                return line
        return self.line

    def scalar(self, key: str) -> Scalar | None:
        value = self.get(key)
        return value if isinstance(value, Scalar) else None


Node = Scalar | Seq | Map


@dataclass(slots=True)
class _Line:
    no: int
    raw: str
    indent: int
    text: str  # content after the indent; rewritten for ``- key: value``


_KEY_TAIL = re.compile(r"\s*(?::(?=\s|$))")
_PROPS = re.compile(r"^(?:[&!][^\s]*\s*)+")
_BLOCK_HEADER = re.compile(r"^[|>][0-9+-]*\s*(?:#.*)?$")


def _quote_opens(text: str, i: int) -> bool:
    """A quote starts a quoted scalar only where a value may start, not inside ``don't``."""
    j = i - 1
    while j >= 0 and text[j] == " ":
        j -= 1
    return j < 0 or text[j] in ":-[{,?"


def _quoted_end(text: str, start: int) -> int:
    """Index just past the closing quote of the quoted scalar opening at ``start``, or -1."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        char = text[i]
        if quote == '"' and char == "\\":
            i += 2
            continue
        if char == quote:
            if quote == "'" and text.startswith("''", i):
                i += 2
                continue
            return i + 1
        i += 1
    return -1


def strip_comment(text: str) -> str:
    """``text`` without a trailing ``# comment`` (a ``#`` at the start or after whitespace, outside quotes)."""
    i = 0
    while i < len(text):
        char = text[i]
        if char in "'\"" and _quote_opens(text, i):
            end = _quoted_end(text, i)
            if end == -1:
                return text
            i = end
            continue
        if char == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _split_key(text: str) -> tuple[str, str] | None:
    """(key, rest) when ``text`` is ``key: rest`` or ``key:``, else None."""
    if not text or text[0] in "[{#" or text.startswith(("- ", "? ")) or text == "-":
        return None
    if text[0] in "'\"":
        end = _quoted_end(text, 0)
        if end == -1:
            return None
        tail = _KEY_TAIL.match(text, end)
        if tail is None:
            return None
        return _unquote(text[:end]), text[tail.end() :].strip()
    for i, char in enumerate(text):
        if char == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].rstrip(), text[i + 1 :].strip()
        if char == "#" and i > 0 and text[i - 1] in " \t":
            return None
    return None


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), text[1:-1])
    return text


def _flow_balance(text: str) -> int:
    depth = 0
    i = 0
    while i < len(text):
        char = text[i]
        if char in "'\"" and _quote_opens(text, i):
            end = _quoted_end(text, i)
            if end == -1:
                break
            i = end
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        i += 1
    return depth


def _split_flow(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        char = body[i]
        if char in "'\"" and _quote_opens(body, i):
            end = _quoted_end(body, i)
            if end == -1:
                break
            i = end
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
        i += 1
    parts.append(body[start:])
    return [p.strip() for p in parts if p.strip()]


class _Parser:
    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0
        self.nodes = 0

    def _count(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise YamlError("too_complex")

    def _skip_blank(self) -> None:
        while self.pos < len(self.lines):
            text = self.lines[self.pos].text
            if text and not text.startswith("#"):
                return
            self.pos += 1

    def document(self) -> Node | None:
        return self.block(0, 0)

    def block(self, indent: int, depth: int) -> Node | None:
        if depth > MAX_DEPTH:
            raise YamlError("too_complex")
        self._skip_blank()
        if self.pos >= len(self.lines):
            return None
        line = self.lines[self.pos]
        if line.indent < indent:
            return None
        if line.text.startswith("- ") or line.text == "-":
            return self.sequence(line.indent, depth)
        if _split_key(strip_comment(line.text)) is not None:
            return self.mapping(line.indent, depth)
        self.pos += 1
        return self._count_node(self.scalar_text(line.text, line.no, line.indent, depth))

    def _count_node(self, node: Node) -> Node:
        self._count()
        return node

    def sequence(self, indent: int, depth: int) -> Seq:
        start = self.lines[self.pos].no
        items: list[Node] = []
        while True:
            self._skip_blank()
            if self.pos >= len(self.lines):
                break
            line = self.lines[self.pos]
            if line.indent != indent or not (line.text.startswith("- ") or line.text == "-"):
                if line.indent > indent:  # stray deeper line: not part of any shape read here
                    self.pos += 1
                    continue
                break
            rest = line.text[1:].lstrip(" ")
            offset = len(line.text) - len(rest)
            self._count()
            if not rest or rest.startswith("#"):
                self.pos += 1
                child = self.block(indent + 1, depth + 1)
                items.append(child if child is not None else Scalar("", line.no))
            else:
                line.indent = indent + offset
                line.text = rest
                child = self.block(indent + offset, depth + 1)
                items.append(child if child is not None else Scalar("", line.no))
        return Seq(items, start)

    def mapping(self, indent: int, depth: int) -> Map:
        start = self.lines[self.pos].no
        entries: list[tuple[str, int, Node]] = []
        while True:
            self._skip_blank()
            if self.pos >= len(self.lines):
                break
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            if line.indent > indent:
                self.pos += 1
                continue
            if line.text.startswith("- ") or line.text == "-":
                break
            split = _split_key(strip_comment(line.text)) if "#" in line.text else _split_key(line.text)
            if split is None:
                self.pos += 1
                continue
            key, rest = split
            self._count()
            self.pos += 1
            entries.append((key, line.no, self.value(rest, line, indent, depth)))
        return Map(entries, start)

    def value(self, rest: str, line: _Line, indent: int, depth: int) -> Node:
        rest = _PROPS.sub("", rest) if rest.startswith(("&", "!")) else rest
        if not rest or rest.startswith("#"):
            self._skip_blank()
            if self.pos < len(self.lines):
                nxt = self.lines[self.pos]
                if nxt.indent > indent:
                    child = self.block(indent + 1, depth + 1)
                    return child if child is not None else Scalar("", line.no)
                if nxt.indent == indent and (nxt.text.startswith("- ") or nxt.text == "-"):
                    return self.sequence(indent, depth + 1)
            return Scalar("", line.no)
        if _BLOCK_HEADER.match(rest):
            return self.block_scalar(rest, line, indent)
        return self.scalar_text(rest, line.no, indent, depth)

    def block_scalar(self, header: str, line: _Line, indent: int) -> Scalar:
        start = self.pos
        i = start
        rows: list[tuple[int, str]] = []
        block_indent = -1
        last = start  # index just past the last non-blank content line
        while i < len(self.lines):
            row = self.lines[i]
            if row.raw.strip() == "":
                rows.append((row.no, ""))
                i += 1
                continue
            if row.indent <= indent:
                break
            if block_indent < 0:
                block_indent = row.indent
            if row.indent < block_indent:
                break
            rows.append((row.no, row.raw[block_indent:]))
            i += 1
            last = i
        self.pos = last
        rows = rows[: last - start]
        lead = 0
        while lead < len(rows) and rows[lead][1] == "":
            lead += 1
        rows = rows[lead:]
        text = "\n".join(t for _, t in rows)
        if header.startswith(">"):
            text = re.sub(r"(?<!\n)\n(?!\n)", " ", text)
        self._count()
        return Scalar(text, rows[0][0] if rows else line.no + 1, block=True)

    def scalar_text(self, rest: str, line_no: int, indent: int, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise YamlError("too_complex")
        rest = _PROPS.sub("", rest) if rest.startswith(("&", "!")) else rest
        if rest.startswith(("[", "{")):
            text = rest
            joined = 0
            while _flow_balance(strip_comment(text)) > 0 and self.pos < len(self.lines) and joined < MAX_JOINED_LINES:
                text += " " + strip_comment(self.lines[self.pos].text)
                self.pos += 1
                joined += 1
            return self.flow(strip_comment(text), line_no, depth)
        if rest.startswith(("'", '"')) and _quoted_end(rest, 0) == -1:
            text = rest
            joined = 0
            while _quoted_end(text, 0) == -1 and self.pos < len(self.lines) and joined < MAX_JOINED_LINES:
                text += " " + self.lines[self.pos].text.strip()
                self.pos += 1
                joined += 1
            end = _quoted_end(text, 0)
            self._count()
            return Scalar(_unquote(text[:end]) if end != -1 else text, line_no, quoted=True)
        if rest.startswith(("'", '"')):
            end = _quoted_end(rest, 0)
            self._count()
            return Scalar(_unquote(rest[:end]), line_no, quoted=True)
        text = strip_comment(rest)
        while self.pos < len(self.lines):  # a plain scalar continues on more indented lines
            nxt = self.lines[self.pos]
            if not nxt.text:
                break
            if nxt.indent <= indent:
                break
            text += " " + strip_comment(nxt.text)
            self.pos += 1
        self._count()
        return Scalar(text, line_no)

    def flow(self, text: str, line_no: int, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise YamlError("too_complex")
        self._count()
        text = text.strip()
        if text.startswith("[") and text.endswith("]"):
            return Seq([self.flow(part, line_no, depth + 1) for part in _split_flow(text[1:-1])], line_no)
        if text.startswith("{") and text.endswith("}"):
            entries: list[tuple[str, int, Node]] = []
            for part in _split_flow(text[1:-1]):
                split = _split_key(part)
                if split is None:
                    entries.append((_unquote(part), line_no, Scalar("", line_no)))
                else:
                    entries.append((split[0], line_no, self.flow(split[1], line_no, depth + 1)))
            return Map(entries, line_no)
        text = _PROPS.sub("", text) if text.startswith(("&", "!")) else text
        if text.startswith(("'", '"')) and _quoted_end(text, 0) == len(text):
            return Scalar(_unquote(text), line_no, quoted=True)
        return Scalar(text, line_no)


def _document_lines(raw_lines: list[tuple[int, str]]) -> list[_Line]:
    lines: list[_Line] = []
    for no, raw in raw_lines:
        body = raw.lstrip(" ")
        indent = len(raw) - len(body)
        text = body.rstrip() if not body.lstrip().startswith("#") else ""
        lines.append(_Line(no, raw, indent, text))
    return lines


def load_documents(text: str) -> list[Node]:
    """The documents of ``text`` that hold a mapping, sequence or scalar. Raises ``YamlError`` over a bound."""
    all_lines = text.splitlines()
    if len(all_lines) > MAX_LINES:
        raise YamlError("too_complex")
    documents: list[list[tuple[int, str]]] = [[]]
    for no, raw in enumerate(all_lines, start=1):
        if len(raw) > MAX_LINE_CHARS:
            raise YamlError("too_complex")
        if raw.startswith("---") and (len(raw) == 3 or raw[3] in " \t"):
            documents.append([])
            rest = raw[3:].strip()
            if rest and not rest.startswith("#"):
                documents[-1].append((no, rest))
            continue
        if raw.startswith("...") and raw[3:].strip() == "":
            documents.append([])
            continue
        documents[-1].append((no, raw))
    result: list[Node] = []
    for rows in documents:
        if len(result) >= MAX_DOCUMENTS:
            raise YamlError("too_complex")
        node = _Parser(_document_lines(rows)).document()
        if node is not None:
            result.append(node)
    return result


def iter_maps(node: Node, depth: int = 0) -> Iterator[Map]:
    """Every mapping under ``node`` (and ``node`` itself), depth-first in source order."""
    if depth > MAX_DEPTH + 8:
        return
    if isinstance(node, Map):
        yield node
        for _, _, value in node.entries:
            yield from iter_maps(value, depth + 1)
    elif isinstance(node, Seq):
        for item in node.items:
            yield from iter_maps(item, depth + 1)


def iter_scalars(node: Node, depth: int = 0) -> Iterator[Scalar]:
    if depth > MAX_DEPTH + 8:
        return
    if isinstance(node, Scalar):
        yield node
    elif isinstance(node, Map):
        for _, _, value in node.entries:
            yield from iter_scalars(value, depth + 1)
    else:
        for item in node.items:
            yield from iter_scalars(item, depth + 1)
