# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A bounded HTML tag scanner in pure Python for ``.html``, ``.vue`` and ``.svelte`` files. Source is never run.

It is not an HTML parser and builds no tree. It finds what the web rules in ``web_rules.py`` read:

- **Start tags** with their attributes (name, raw value, line and column of the attribute). Values may be double
  quoted, single quoted or bare; a Svelte attribute value that starts with ``{`` runs to the matching ``}``, and a
  bare ``{...spread}`` or ``{shorthand}`` is kept as an attribute named by its text. ``>`` inside a quoted value
  does not end the tag, so ``:disabled="a > b"`` is one tag.
- **Raw-text blocks:** the body of ``<script>`` and ``<style>`` runs to the next ``</script`` or ``</style``, and a
  Vue ``<template lang="pug">`` (any language other than HTML) is skipped the same way. Bodies are returned as
  offsets so the caller can run the JavaScript and CSS rules on them with the right line numbers.
- **Comments** (``<!-- -->``), declarations (``<!DOCTYPE``) and ``<![CDATA[`` sections are skipped. End tags are
  ignored.

Malformed input never raises: an unterminated quote, tag or comment ends at the end of the file. More than
``MAX_TAGS`` start tags give ``None`` (the file is reported as ``too_complex``); a tag keeps at most
``MAX_ATTRS`` attributes and a value at most ``MAX_VALUE`` characters. Every scan step advances, and each ``find``
runs once per position, so the work is linear in the file size.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

MAX_TAGS = 200_000
MAX_ATTRS = 256
MAX_VALUE = 65_536
MAX_BRACE_SPAN = 8192  # a Svelte {expression} longer than this is not followed to its closing brace

_TAG_NAME = re.compile(r"[A-Za-z][^\s/>]*")
_ATTR_NAME = re.compile(r"[^\s=/>\"']+")
_WS = re.compile(r"\s*")
_BARE_VALUE = re.compile(r"[^\s>]+")
_RAW_END = {
    "script": re.compile(r"</script\b", re.IGNORECASE),
    "style": re.compile(r"</style\b", re.IGNORECASE),
    "template": re.compile(r"</template\b", re.IGNORECASE),
}


@dataclass(frozen=True, slots=True)
class Attr:
    name: str  # as written
    value: str | None  # None for an attribute without a value; the text between the quotes otherwise
    line: int  # 1-based line of the attribute name
    col: int

    @property
    def lname(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Tag:
    name: str  # lower-cased
    raw_name: str
    attrs: tuple[Attr, ...]
    line: int
    col: int
    start: int  # offset of '<'
    end: int  # offset after '>'

    def attr(self, name: str) -> Attr | None:
        """The first attribute whose lower-cased name is ``name``."""
        return next((a for a in self.attrs if a.lname == name), None)


@dataclass(frozen=True, slots=True)
class Block:
    """The body of a ``<script>`` or ``<style>`` element: ``text[start:end]``."""

    tag: Tag
    start: int
    end: int
    line: int  # 1-based line of ``start``
    col: int  # 1-based column of ``start``


@dataclass(slots=True)
class Doc:
    tags: list[Tag] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    markup: list[tuple[int, int]] = field(default_factory=list)  # offset ranges outside the raw-text blocks


class Positions:
    """Line and column of an offset, by bisecting the line starts."""

    def __init__(self, text: str) -> None:
        self.starts = [0, *(m.end() for m in re.finditer(r"\r\n|\r|\n", text))]

    def line_col(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self.starts, offset)
        return line, offset - self.starts[line - 1] + 1


def brace_end(text: str, open_: int, limit: int | None = None) -> int:
    """Offset after the ``}`` that closes the ``{`` at ``open_``, or -1. Strings and template literals are skipped."""
    n = len(text) if limit is None else min(len(text), limit)
    depth = 0
    i = open_
    stop = min(n, open_ + MAX_BRACE_SPAN)
    while i < stop:
        char = text[i]
        if char in "'\"`":
            j = i + 1
            while j < stop and text[j] != char:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def scan(text: str) -> Doc | None:
    """Start tags and raw-text blocks of ``text``, or None when there are more than ``MAX_TAGS`` start tags."""
    doc = Doc()
    pos = Positions(text)
    n = len(text)
    i = 0
    markup_from = 0
    while i < n:
        lt = text.find("<", i)
        if lt < 0:
            break
        nxt = text[lt + 1 : lt + 2]
        if text.startswith("<!--", lt):
            end = text.find("-->", lt + 4)
            i = n if end < 0 else end + 3
            continue
        if nxt in ("!", "?", "/"):
            end = text.find(">", lt + 2)
            i = n if end < 0 else end + 1
            continue
        match = _TAG_NAME.match(text, lt + 1)
        if match is None:
            i = lt + 1
            continue
        if len(doc.tags) >= MAX_TAGS:
            return None
        tag, i = _start_tag(text, lt, match, pos)
        doc.tags.append(tag)
        raw = tag.name if tag.name in _RAW_END else ""
        if raw == "template":
            lang = tag.attr("lang")
            raw = "template" if lang is not None and (lang.value or "").lower() not in ("", "html") else ""
        if raw and text[tag.end - 2 : tag.end] != "/>":
            closing = _RAW_END[raw].search(text, i)
            body_end = n if closing is None else closing.start()
            if raw != "template":
                line, col = pos.line_col(i)
                doc.blocks.append(Block(tag, i, body_end, line, col))
                doc.markup.append((markup_from, i))
                markup_from = body_end
            i = body_end
    doc.markup.append((markup_from, n))
    return doc


def _attribute(text: str, i: int, pos: Positions) -> tuple[Attr, int] | None:
    """The attribute starting at ``i`` and the offset after it, or None when no name starts there."""
    n = len(text)
    attr_name = _ATTR_NAME.match(text, i)
    if attr_name is None:
        return None
    line, col = pos.line_col(i)
    i = attr_name.end()
    j = _WS.match(text, i).end()  # type: ignore[union-attr]
    value: str | None = None
    if j < n and text[j] == "=":
        j = _WS.match(text, j + 1).end()  # type: ignore[union-attr]
        if j < n and text[j] in "\"'":
            close = text.find(text[j], j + 1)
            if close < 0:
                value, i = text[j + 1 : j + 1 + MAX_VALUE], n
            else:
                value, i = text[j + 1 : close][:MAX_VALUE], close + 1
        elif j < n and text[j] == "{":
            end = brace_end(text, j)
            end = j + 1 if end < 0 else end
            value, i = text[j:end][:MAX_VALUE], end
        else:
            bare = _BARE_VALUE.match(text, j)
            if bare is None:
                value, i = "", j
            else:
                value, i = bare.group(0)[:MAX_VALUE], bare.end()
    return Attr(attr_name.group(0), value, line, col), i


def _start_tag(text: str, lt: int, name: re.Match[str], pos: Positions) -> tuple[Tag, int]:
    n = len(text)
    i = name.end()
    attrs: list[Attr] = []
    while i < n:
        i = _WS.match(text, i).end()  # type: ignore[union-attr]
        if i >= n:
            break
        char = text[i]
        if char == ">":
            i += 1
            break
        if text.startswith("/>", i):
            i += 2
            break
        if char == "/":
            i += 1
            continue
        if char == "{":  # a Svelte {...spread} or {shorthand}
            end = brace_end(text, i)
            end = i + 1 if end < 0 else end
            line, col = pos.line_col(i)
            if len(attrs) < MAX_ATTRS:
                attrs.append(Attr(text[i:end][:MAX_VALUE], None, line, col))
            i = end
            continue
        parsed = _attribute(text, i, pos)
        if parsed is None:
            i += 1
            continue
        attr, i = parsed
        if len(attrs) < MAX_ATTRS:
            attrs.append(attr)
    line, col = pos.line_col(lt)
    raw_name = name.group(0)
    return Tag(raw_name.lower(), raw_name, tuple(attrs), line, col, lt, i), i
