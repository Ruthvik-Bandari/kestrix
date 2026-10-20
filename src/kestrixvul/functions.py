# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Function extraction from whole Python, JavaScript and TypeScript files (no dependencies).

Used for the commits mined from the GitHub Advisory Database, where no lizard rows exist, and for
the unchanged functions sampled as negatives.

* **Python**: the standard library ``ast``. A unit is a ``def`` (or ``async def``) at module or
  class level, named ``Class.method``; functions nested in a function belong to it. Its span is the
  ``def`` line to ``end_lineno`` (decorators excluded, as in lizard's rows). Files ``ast`` cannot
  parse (Python 2) fall back to an indentation scan.
* **JavaScript/TypeScript**: the token stream of ``kestrix_scan.js_tokens`` (strings, templates,
  regular expressions and JSX handled), with braces matched. A unit is a named function body:
  ``function f() {}``, a method ``m() {}`` (``Class.m`` inside ``class Class``), or a function or
  block-bodied arrow assigned to a name (``const f = () => {}``, ``f: function () {}``). Functions
  nested in a unit belong to it. Anonymous functions are transparent, except that an anonymous
  function outside every unit and containing none is returned as a *shadow* unit: never labelled,
  but counted as a changed function by OneFunc when it changed.
"""

from __future__ import annotations

import ast
import re
import warnings
from collections import Counter
from dataclasses import dataclass

from kestrix_scan.js_tokens import NAME, PUNCT, TPL_HEAD, TPL_TAIL, Token, tokenize

from .labels import Change

PY_EXT = (".py",)
JS_EXT = (".js", ".jsx", ".mjs", ".cjs")
TS_EXT = (".ts", ".tsx", ".mts", ".cts")
# Changed files in these languages count as at least one changed function for OneFunc (lizard
# parses them in CVEfixes and MoreFixes); their functions are not extracted.
OTHER_CODE_EXT = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java", ".cs", ".m", ".mm", ".swift", ".rb", ".php",
    ".scala", ".go", ".lua", ".rs", ".kt", ".kts", ".sol", ".erl", ".f90", ".vue", ".svelte", ".pl", ".pm",
)  # fmt: skip
ANONYMOUS = "(anonymous)"
CONTROL = {"if", "for", "while", "switch", "catch", "with", "return", "typeof", "do", "else", "try", "finally"}
MODIFIERS = {"async", "static", "get", "set", "public", "private", "protected", "readonly", "override", "abstract"}
OPEN = {"(": ")", "[": "]", "{": "}"}


@dataclass(frozen=True)
class Func:
    name: str
    start: int  # 1-based first line
    end: int  # 1-based last line
    code: str
    shadow: bool = False  # an anonymous JS function outside every unit (OneFunc counting only)


def language_of(path: str) -> str | None:
    lowered = path.lower()
    if lowered.endswith(PY_EXT):
        return "python"
    if lowered.endswith(JS_EXT):
        return "javascript"
    if lowered.endswith(TS_EXT) and not lowered.endswith(".d.ts"):
        return "typescript"
    return None


def is_other_code(path: str) -> bool:
    return path.lower().endswith(OTHER_CODE_EXT)


def _cut(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1 : end]).strip("\n")


# --- Python ---------------------------------------------------------------------------------


def python_functions(text: str) -> list[Func]:
    try:
        with warnings.catch_warnings():  # invalid escapes in mined code are the project's, not ours
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _indented_functions(text)
    lines = text.splitlines()
    out: list[Func] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = child.end_lineno or child.lineno
                out.append(Func(prefix + child.name, child.lineno, end, _cut(lines, child.lineno, end)))
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            elif not isinstance(child, ast.Lambda):
                visit(child, prefix)

    visit(tree, "")
    return out


PY_DEF = re.compile(r"^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)")
PY_CLASS = re.compile(r"^([ \t]*)class[ \t]+([A-Za-z_]\w*)")


def _indent(line: str) -> int:
    return len(line.expandtabs(8)) - len(line.expandtabs(8).lstrip())


def _indented_functions(text: str) -> list[Func]:
    """Indentation scan for Python 2 files: ``def`` blocks end at the next line indented no deeper."""
    lines = text.splitlines()
    out: list[Func] = []
    classes: list[tuple[int, str]] = []
    current: tuple[int, str, int] | None = None  # (indent, name, start)
    last_code = 0
    in_string: str | None = None
    for no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if in_string is not None:
            if line.count(in_string) % 2 == 1:
                in_string = None
            last_code = no
            continue
        if not stripped or stripped.startswith("#"):
            continue
        level = _indent(line)
        if current is not None and level <= current[0]:
            out.append(Func(current[1], current[2], last_code, _cut(lines, current[2], last_code)))
            current = None
        while classes and level <= classes[-1][0]:
            classes.pop()
        if current is None:
            m = PY_DEF.match(line)
            c = PY_CLASS.match(line)
            if m:
                prefix = "".join(f"{name}." for _, name in classes)
                current = (level, prefix + m.group(2), no)
            elif c:
                classes.append((level, c.group(2)))
        for quote in ('"""', "'''"):
            if line.count(quote) % 2 == 1:
                in_string = quote
                break
        last_code = no
    if current is not None:
        out.append(Func(current[1], current[2], last_code, _cut(lines, current[2], last_code)))
    return out


# --- JavaScript / TypeScript ----------------------------------------------------------------


def _match(toks: list[Token]) -> list[int]:
    """Index of the matching closer (or opener) per bracket token; -1 elsewhere or when unmatched."""
    match = [-1] * len(toks)
    stack: list[int] = []
    for i, tok in enumerate(toks):
        if (tok.kind == PUNCT and tok.value in OPEN) or tok.kind == TPL_HEAD:
            stack.append(i)
        elif (tok.kind == PUNCT and tok.value in {")", "]", "}"}) or tok.kind == TPL_TAIL:
            want = {")": "(", "]": "[", "}": "{"}.get(tok.value) if tok.kind == PUNCT else None
            for depth in range(len(stack) - 1, max(-1, len(stack) - 4), -1):
                opener = toks[stack[depth]]
                ok = opener.kind == TPL_HEAD if want is None else (opener.kind == PUNCT and opener.value == want)
                if ok:
                    match[stack[depth]] = i
                    match[i] = stack[depth]
                    del stack[depth:]
                    break
    return match


def _is(tok: Token, *values: str) -> bool:
    return tok.kind == PUNCT and tok.value in values


def _back_over_generics(toks: list[Token], k: int) -> int:
    """From a ``>`` at ``k``, the index before the matching ``<`` (or -1)."""
    depth = 0
    for j in range(k, max(-1, k - 80), -1):
        if _is(toks[j], ">"):
            depth += 1
        elif _is(toks[j], "<"):
            depth -= 1
            if depth == 0:
                return j - 1
        elif _is(toks[j], ";", "{", "}"):
            return -1
    return -1


def _return_type_close(toks: list[Token], k: int) -> int | None:
    """For ``(...): Type {``, the ``)`` before the annotation."""
    for j in range(k, max(-1, k - 40), -1):
        if _is(toks[j], ":") and j >= 1 and _is(toks[j - 1], ")"):
            return j - 1
        if _is(toks[j], ";", "{", "}", "=", "=>"):
            return None
    return None


def _assigned(toks: list[Token], start: int) -> tuple[str, int]:
    """(name, token index) a function expression starting at ``start`` is assigned to, else ("", start)."""
    k = start - 1
    if k >= 0 and toks[k].kind == NAME and toks[k].value == "async":
        k -= 1
    if k >= 1 and _is(toks[k], "=", ":") and toks[k - 1].kind == NAME:
        at = k - 1
        while at >= 2 and _is(toks[at - 1], ".") and toks[at - 2].kind == NAME:  # exports.f = function
            at -= 2
        return toks[k - 1].value, at
    return "", start


def _head(toks: list[Token], match: list[int], brace: int) -> tuple[str, int] | None:
    """(name, first token) when the ``{`` at ``brace`` opens a function body, else None."""
    prev = brace - 1
    if prev < 0:
        return None
    if _is(toks[prev], "=>"):
        k = prev - 1
        if k < 0:
            return None
        if toks[k].kind == NAME:
            start = k - 1 if k >= 1 and toks[k - 1].value == "async" else k
        else:
            paren = k if _is(toks[k], ")") else _return_type_close(toks, k)
            if paren is None or match[paren] < 0:
                return None
            start = match[paren]
            if start >= 1 and _is(toks[start - 1], ">"):
                g = _back_over_generics(toks, start - 1)
                start = g + 1 if g >= 0 else start
            if start >= 1 and toks[start - 1].kind == NAME and toks[start - 1].value == "async":
                start -= 1
        name, at = _assigned(toks, start)
        return name, min(at, start)
    if _is(toks[prev], ")"):
        close: int | None = prev
    elif toks[prev].kind == NAME or _is(toks[prev], ">", "]"):
        close = _return_type_close(toks, prev)
    else:
        close = None
    if close is None or match[close] < 0 or match[close] >= close:
        return None
    k = match[close] - 1
    if k >= 0 and _is(toks[k], ">"):
        k = _back_over_generics(toks, k)
    if k < 0:
        return None
    before = toks[k]
    if before.kind == NAME and before.value == "function":
        name, at = _assigned(toks, k)
        return name, min(at, k)
    if _is(before, "*") and k >= 1 and toks[k - 1].value == "function":
        name, at = _assigned(toks, k - 1)
        return name, min(at, k - 1)
    if before.kind != NAME or before.value in CONTROL:
        return None
    if k >= 1 and toks[k - 1].kind == NAME and toks[k - 1].value == "function":
        return before.value, k - 1
    if k >= 2 and _is(toks[k - 1], "*") and toks[k - 2].value == "function":
        return before.value, k - 2
    if k >= 1 and _is(toks[k - 1], ".", "?."):
        return None  # obj.method(x) followed by a block
    start = k
    while start >= 1 and toks[start - 1].kind == NAME and toks[start - 1].value in MODIFIERS:
        start -= 1
    return before.value, start


def _class_name(toks: list[Token], brace: int) -> str | None:
    """``class Name ... {``: the class name when the ``{`` at ``brace`` opens a class body."""
    for j in range(brace - 1, max(-1, brace - 30), -1):
        tok = toks[j]
        if tok.kind == NAME and tok.value == "class":
            nxt = toks[j + 1] if j + 1 < brace else None
            return nxt.value if nxt is not None and nxt.kind == NAME and nxt.value != "extends" else ANONYMOUS
        if _is(tok, ";", "{", "}", "(", ")", "=>"):
            return None
    return None


def js_functions(text: str, language: str, path: str = "") -> list[Func] | None:
    """Units and shadow units of a JS/TS file, or None when the tokenizer gives up (too complex)."""
    lowered = path.lower()
    toks = tokenize(text, jsx=language == "javascript" or lowered.endswith(".tsx"), tsx=lowered.endswith(".tsx"))
    if toks is None:
        return None
    match = _match(toks)
    lines = text.splitlines()
    # (open brace, its close, name or "", first token)
    found: list[tuple[int, int, str, int]] = []
    classes: list[tuple[int, int, str]] = []
    for i, tok in enumerate(toks):
        if not _is(tok, "{") or match[i] <= i:
            continue
        cls = _class_name(toks, i)
        if cls is not None:
            classes.append((i, match[i], cls))
            continue
        head = _head(toks, match, i)
        if head is not None:
            name, first = head
            found.append((i, match[i], name, first))
    named = [f for f in found if f[2]]

    def inside(lo: int, hi: int, spans: list[tuple[int, int, str, int]]) -> bool:
        return any(o < lo and hi < c for o, c, _, _ in spans)

    out: list[Func] = []
    anonymous = [f for f in found if not f[2]]
    for open_, close, own, first in found:
        if inside(open_, close, named):
            continue
        if own:
            owner = [c for c in classes if c[0] < open_ and close < c[1]]
            name = f"{owner[-1][2]}.{own}" if owner and "." not in own else own
        elif any(open_ < o and c < close for o, c, _, _ in named) or inside(open_, close, anonymous):
            continue
        else:
            name = ANONYMOUS
        start, end = toks[first].line, toks[close].end_line
        out.append(Func(name, start, end, _cut(lines, start, end), shadow=not own))
    return sorted(out, key=lambda f: (f.start, f.end))


def functions(text: str, language: str, path: str = "") -> list[Func] | None:
    return python_functions(text) if language == "python" else js_functions(text, language, path)


# --- changed functions between two versions -------------------------------------------------


def _keyed(funcs: list[Func]) -> dict[tuple[str, int], Func]:
    seen: Counter[str] = Counter()
    out: dict[tuple[str, int], Func] = {}
    for f in funcs:
        out[(f.name, seen[f.name])] = f
        seen[f.name] += 1
    return out


@dataclass
class FileDiff:
    changes: list[Change]  # changed named units (paired, deleted or added)
    shadow_changed: int  # changed anonymous shadow units
    unchanged: list[Func]  # named units identical in both versions (before-version spans)


def diff_functions(before: list[Func], after: list[Func]) -> FileDiff:
    """Pair units by (name, occurrence); a unit is changed when its text differs or it has one side only."""
    b, a = _keyed(before), _keyed(after)
    changes: list[Change] = []
    unchanged: list[Func] = []
    shadow = 0
    for key in sorted(set(b) | set(a), key=lambda k: ((b.get(k) or a[k]).start, k)):
        old, new = b.get(key), a.get(key)
        if old is not None and new is not None and old.code == new.code:
            if not old.shadow:
                unchanged.append(old)
            continue
        if (old or new) is not None and (old or new).shadow:  # type: ignore[union-attr]
            shadow += 1
            continue
        kind = "paired" if old and new else ("deleted" if old else "added")
        changes.append(Change(key[0], old.code if old else None, new.code if new else None, kind))
    return FileDiff(changes, shadow, unchanged)
