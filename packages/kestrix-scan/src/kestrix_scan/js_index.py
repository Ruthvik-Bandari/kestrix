# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A structural index over JavaScript/TypeScript tokens: the matcher the ``js.*`` rules are written against.

There is no syntax tree. The index knows:

- **Groups:** the matching bracket of every ``(``, ``[``, ``{`` and template, and the innermost group that
  contains each token, so a call's arguments are split at top-level commas.
- **Member chains** read backwards from a call's ``(`` (``a.b?.c``, ``require('x').y``, ``f(...).g``,
  ``a[0]``) and forwards from a name.
- **Functions:** a ``{`` after ``=>``, or after ``(...)`` that follows a name that is not ``if``/``for``/
  ``while``/``switch``/``catch``/``with``, or ``function``, opens a function body; a TypeScript return type
  between ``)`` and ``{`` is skipped. Each body is a scope with its parameter names.
- **Bindings** per scope: ``const``/``let``/``var`` declarators (with destructuring), plain and compound
  assignments to a name, ``for (... of|in x)`` variables and the first parameter of a callback passed to
  ``forEach``/``map``/``filter``/... A binding records the token span of its value.
- **Module aliases:** ``import`` (default, namespace, named, ``as``), ``require`` (whole module, destructured,
  ``require('m').x``), ``await import('m')``, ``promisify(x)``, and ``const y = x.z`` copies, so
  ``cp.exec``, ``execSync`` from ``node:child_process`` and ``run`` from ``{ exec: run }`` all resolve to
  ``child_process.exec``. Globals (``eval``, ``document``, ``fetch`` ...) resolve to themselves unless the
  file declares the name.

On top of that it answers two questions about an expression span: is it a **literal** (strings, numbers and
templates, joined with ``+``, or names whose every binding is one), and does **tainted data** reach it.

**Taint** is lightweight and stays inside a function and the functions around it (closures); it never crosses
into a called function. Sources:

- ``request`` (high): Express ``req``/``request`` ``.params``/``.query``/``.body``/``.headers``/``.cookies``/
  ``.signedCookies``/``.files`` and ``req.param()``/``req.get()``/``req.header()``; Koa ``ctx.query``/
  ``ctx.params``/``ctx.request.query|body``/``ctx.get()``/``ctx.headers``; Fetch-API ``request.json()``/``formData()``/
  ``text()``; in a Next.js file the ``params``/``searchParams`` parameters, ``context.params`` and a ``'use server'``
  action's ``FormData`` argument; NestJS parameters decorated ``@Query()``/``@Body()``/``@Param()``/``@Headers()``.
  The base name must be a parameter of some function in the file.
- ``dom`` (high): ``location``, ``window.location``, ``document.location``, ``document.URL``,
  ``document.documentURI``, ``window.name``, the ``data`` of the first parameter of a ``message`` event
  listener (``addEventListener('message', ...)`` or ``onmessage = ...``), and React Router's
  ``useSearchParams()``/``useParams()``/``useLocation()`` and Next's ``useSearchParams()``/``useParams()``.
- ``llm`` (high): the result of ``....chat.completions.create(...)``, ``....messages.create(...)``,
  ``....responses.create(...)`` and ``....completions.create(...)`` in a file that imports ``openai`` or
  ``@anthropic-ai/sdk``.

It flows through bindings, ``+`` and templates, ``||``/``??``/``&&``, ternary branches, ``await``, arrays and
object literals, member access and indexing, string and array methods called on tainted data, and the calls
``path.join``/``resolve``/``normalize``, ``String``, ``decodeURIComponent``, ``JSON.parse``, ``Buffer.from``,
``Object.keys``/``values``/``entries``, ``Array.from``, ``new URL`` (only its first argument: the base of ``new URL(x, base)`` only completes a relative ``x``) and
``new URLSearchParams``. Every other
call returns clean data. Comparisons, ``typeof``, ``!`` and numeric conversion (``Number``, ``parseInt``,
``parseFloat``) give clean values. Sanitizers clear one sink class: ``path.basename`` (path),
``DOMPurify.sanitize``, ``sanitizeHtml``, ``escapeHtml``, ``encodeURIComponent`` ... (html), ``shell-quote``
``quote`` (shell), ``escape``/``escapeId``/``format`` of mysql (sql). A string that starts with a literal
scheme and host (``'https://api.example.com/' + x``) is clean for URL and redirect sinks, and one that
starts with ``/`` and a path character is clean for redirects.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from .js_tokens import JSX, NAME, NUM, PUNCT, REGEX, STR, TPL, TPL_HEAD, TPL_MID, TPL_TAIL, Token
from .models import Confidence, TraceStep

MAX_DEPTH = 40  # bound on recursive span evaluation
MAX_HOPS = 6  # name -> binding hops followed
MAX_ORIGINS = 4
MAX_TRACE = 8

SHELL, CODE, PATH, HTML, URL, REDIRECT, SQL, KEY = (
    "shell",
    "code",
    "path",
    "html",
    "url",
    "redirect",
    "sql",
    "key",
)  # sink classes
CONFIDENCE: dict[str, Confidence] = {"request": "high", "dom": "high", "llm": "high"}
_KIND_ORDER = {"llm": 0, "request": 1, "dom": 2}

_OPENERS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = {")": "(", "]": "[", "}": "{"}
_CONTROL = frozenset({"if", "for", "while", "switch", "catch", "with", "return", "typeof", "await", "new", "yield"})
_NOT_CALLEE = _CONTROL | {"function", "async"}
_MODIFIERS = frozenset(
    {"async", "static", "public", "private", "protected", "readonly", "override", "get", "set", "abstract", "declare"}
)
_DECLARE = frozenset({"const", "let", "var"})
_NOT_OPERAND = frozenset(
    {"in", "of", "instanceof", "typeof", "new", "await", "void", "delete", "return", "throw", "case", "yield"}
)
_ASSIGN_OPS = frozenset({"=", "+=", "||=", "??=", "&&="})
_ITER_METHODS = frozenset({"forEach", "map", "filter", "find", "some", "every", "flatMap", "findLast"})
GLOBALS = frozenset(
    {
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "setImmediate",
        "document",
        "location",
        "fetch",
        "Math",
        "process",
        "JSON",
        "String",
        "Number",
        "parseInt",
        "parseFloat",
        "Boolean",
        "decodeURIComponent",
        "decodeURI",
        "encodeURIComponent",
        "encodeURI",
        "Buffer",
        "Object",
        "Array",
        "URL",
        "URLSearchParams",
        "Response",
        "require",
        "jQuery",
        "$",
    }
)
_GLOBAL_OBJECTS = frozenset({"window", "globalThis", "self"})
_LLM_MODULES = frozenset({"openai", "@anthropic-ai/sdk"})
_LLM_TAILS = (
    ("chat", "completions", "create"),
    ("messages", "create"),
    ("responses", "create"),
    ("completions", "create"),
)
_REQUEST_FIELDS = frozenset(
    {
        "params",
        "query",
        "body",
        "headers",
        "cookies",
        "signedCookies",
        "files",
        "url",  # http.createServer, Express, Fastify: the request target the client wrote
        "originalUrl",
        "path",
        "baseUrl",
        "payload",  # hapi
        "rawBody",
        "nextUrl",  # Next.js middleware and route handlers
    }
)
_REQUEST_CALLS = frozenset({"param", "get", "header"})
_KOA_FIELDS = frozenset({"query", "params", "querystring", "url", "originalUrl", "path", "headers"})
_ROUTER_HOOKS = frozenset({"useSearchParams", "useParams", "useLocation"})
_ROUTER_MODULES = ("react-router", "next/navigation")
_BODY_READERS = frozenset({"json", "formData", "text", "arrayBuffer", "blob"})  # Fetch-API Request (Next.js, Remix)
_NEXT_PARAMS = frozenset({"params", "searchParams"})  # Next.js route handler context and page props
_FORM_PARAMS = frozenset({"formData", "form", "fd"})  # a 'use server' action's FormData argument
_NEST_SOURCES = {
    "Query": "NestJS @Query()",
    "Body": "NestJS @Body()",
    "Param": "NestJS @Param()",
    "Headers": "NestJS @Headers()",
}
_DOM_DOCUMENT = frozenset({"location", "URL", "documentURI"})
_PROPAGATE_CALLS = frozenset(
    {
        "path.join",
        "path.resolve",
        "path.normalize",
        "path.posix.join",
        "path.win32.join",
        "String",
        "decodeURIComponent",
        "decodeURI",
        "JSON.parse",
        "Buffer.from",
        "Object.keys",
        "Object.values",
        "Object.entries",
        "Array.from",
        "URL",
        "URLSearchParams",
        "String.raw",
        "Object.fromEntries",
    }
)
_NUMERIC_CALLS = frozenset({"Number", "parseInt", "parseFloat", "Boolean", "Number.parseInt", "Number.parseFloat"})
_CLEARING_CALLS: dict[str, frozenset[str]] = {
    "path.basename": frozenset({PATH}),
    "path.posix.basename": frozenset({PATH}),
    "path.win32.basename": frozenset({PATH}),
    "encodeURIComponent": frozenset({HTML}),
    "shell-quote.quote": frozenset({SHELL}),
    "mysql.escape": frozenset({SQL}),
    "mysql.escapeId": frozenset({SQL}),
    "mysql.format": frozenset({SQL}),
    "mysql2.escape": frozenset({SQL}),
    "mysql2.format": frozenset({SQL}),
    "sqlstring.escape": frozenset({SQL}),
    "pg-format": frozenset({SQL}),
}
# Calls whose last name sanitizes HTML whatever the receiver (DOMPurify.sanitize, purify.sanitize, he.encode ...).
_HTML_SANITIZER_NAMES = frozenset({"sanitize", "sanitizeHtml", "escapeHtml", "escapeHTML", "escape", "encode"})
_PROPAGATE_METHODS = frozenset(
    {
        "toString",
        "valueOf",
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toLocaleLowerCase",
        "toLocaleUpperCase",
        "normalize",
        "replace",
        "replaceAll",
        "slice",
        "substring",
        "substr",
        "split",
        "concat",
        "padStart",
        "padEnd",
        "repeat",
        "at",
        "join",
        "flat",
        "get",
        "getAll",
        "toJSON",
        "map",
        "filter",
        "values",
    }
)
_FIXED_HOST = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]+[/?#]")
_LOCAL_PATH = re.compile(r"^/[^/\\]")


def is_punct(token: Token, *values: str) -> bool:
    return token.kind == PUNCT and token.value in values


_LODASH_PACKAGES = {"lodash.merge": "merge", "lodash.mergewith": "mergeWith", "lodash.defaultsdeep": "defaultsDeep"}


def module_name(raw: str) -> str:
    """``node:fs`` and ``fs/promises`` -> ``fs``; ``lodash-es`` -> ``lodash``; ``lodash/merge`` and ``lodash.merge`` -> ``lodash.merge``."""
    name = raw.removeprefix("node:")
    if name in ("fs/promises", "fs-extra"):
        return "fs"
    if name in _LODASH_PACKAGES:
        return "lodash." + _LODASH_PACKAGES[name]
    for package in ("lodash-es", "lodash"):
        if name == package:
            return "lodash"
        if name.startswith(package + "/"):
            return "lodash." + name[len(package) + 1 :]
    return name


@dataclass(frozen=True)
class Seg:
    """One link of a member chain: a name, a call (``open`` is its ``(``) or an index (``open`` is its ``[``)."""

    kind: str  # "name", "call" or "index"
    value: str  # the name; for an index with a string key, the key
    index: int  # token index of the name, or of the opening bracket


@dataclass(frozen=True)
class Chain:
    segs: tuple[Seg, ...]
    start: int  # first token of the chain
    end: int  # one past the last token


@dataclass(frozen=True)
class Call:
    callee: Chain  # the chain up to, not including, this call's '('
    open: int  # the call's '('
    args: tuple[tuple[int, int], ...]  # token spans of the arguments


@dataclass(frozen=True)
class Binding:
    name: str
    pos: int  # token index of the bound name
    lo: int  # value span (lo == hi: no value, for example a parameter or a function declaration)
    hi: int
    kind: str  # "value", "iter" (an element of the span), "param" or "decl"


@dataclass
class Scope:
    id: int
    open: int  # the body's '{' (-1 for the module)
    close: int
    parent: int | None
    name: str = ""  # the function's name when it has one


@dataclass(frozen=True)
class Origin:
    kind: str  # "request", "dom" or "llm"
    label: str  # for example "Express req.query"
    trace: tuple[TraceStep, ...]
    cleared: frozenset[str] = frozenset()  # sink classes a sanitizer or a fixed prefix made safe


def best(origins: list[Origin], sink: str, kinds: frozenset[str] | None = None) -> Origin | None:
    usable = [o for o in origins if sink not in o.cleared and (kinds is None or o.kind in kinds)]
    return min(usable, key=lambda o: _KIND_ORDER[o.kind]) if usable else None


def _add(origins: list[Origin], new: list[Origin]) -> list[Origin]:
    out = list(origins)
    for origin in new:
        if len(out) >= MAX_ORIGINS:
            break
        if all(
            (o.kind, o.trace[0].line, o.cleared) != (origin.kind, origin.trace[0].line, origin.cleared) for o in out
        ):
            out.append(origin)
    return out


class Index:
    def __init__(self, tokens: list[Token], lines: list[str], *, next_context: bool = False) -> None:
        self.toks = tokens
        self.next_context = next_context  # a Next.js file: route handler params, server actions
        self.n = len(tokens)
        self.lines = lines
        self.match = [-1] * self.n
        self.parent = [-1] * self.n
        self.tpl_parts: dict[int, list[int]] = {}
        self.scopes: list[Scope] = [Scope(0, -1, self.n, None)]
        self.scope_of = [0] * self.n
        self.bindings: dict[tuple[int, str], list[Binding]] = {}
        self._bound: set[int] = set()  # token indexes of names already bound by a declaration or a parameter
        self.aliases: dict[str, str] = {}
        self.declared: set[str] = set()
        self.params: set[str] = set()
        self.message_params: set[tuple[int, str]] = set()
        self.source_params: dict[tuple[int, str], str] = {}  # (function scope, parameter name) -> request source label
        self.modules: set[str] = set()
        self.strings = frozenset(t.value for t in tokens if t.kind == STR)
        self._use_server = next_context and "use server" in self.strings
        self._memo: dict[tuple[int, int], list[Origin]] = {}
        self._ends: dict[int, int] = {}  # expr_end memo, without and with a top-level comma ending the expression
        self._ends_comma: dict[int, int] = {}
        self._active: set[tuple[int, int]] = set()
        self._match_groups()
        self._find_scopes()
        self._collect_bindings()
        self._collect_aliases()
        self.calls = list(self._calls())

    # ----- groups

    def _match_groups(self) -> None:
        stack: list[int] = []
        toks = self.toks
        for i, tok in enumerate(toks):
            self.parent[i] = stack[-1] if stack else -1
            kind = tok.kind
            if kind == PUNCT and tok.value in _OPENERS:
                stack.append(i)
            elif kind == TPL_HEAD:
                stack.append(i)
                self.tpl_parts[i] = [i]
            elif kind == TPL_MID:
                if stack and toks[stack[-1]].kind == TPL_HEAD:
                    self.tpl_parts[stack[-1]].append(i)
            elif (kind == PUNCT and tok.value in _CLOSERS) or kind == TPL_TAIL:
                want = _CLOSERS.get(tok.value) if kind == PUNCT else None
                for depth in range(len(stack) - 1, max(-1, len(stack) - 4), -1):
                    opener = toks[stack[depth]]
                    if (want is not None and is_punct(opener, want)) or (want is None and opener.kind == TPL_HEAD):
                        for unclosed in stack[depth + 1 :]:
                            self.match[unclosed] = i
                        head = stack[depth]
                        self.match[head] = i
                        self.match[i] = head
                        if kind == TPL_TAIL:
                            self.tpl_parts[head].append(i)
                        del stack[depth:]
                        break
        for unclosed in stack:
            self.match[unclosed] = self.n

    def close_of(self, i: int) -> int:
        """The matching closer of the opener at ``i`` (``n`` when it never closes)."""
        end = self.match[i]
        return end if end > i else self.n

    def template_exprs(self, head: int) -> list[tuple[int, int]]:
        parts = self.tpl_parts.get(head, [head])
        return [(parts[k] + 1, parts[k + 1]) for k in range(len(parts) - 1)]

    def split(self, lo: int, hi: int, sep: str = ",") -> list[tuple[int, int]]:
        """Top-level pieces of ``lo:hi`` separated by ``sep``; empty pieces are dropped."""
        pieces = []
        start = k = lo
        while k < hi:
            tok = self.toks[k]
            if (tok.kind == PUNCT and tok.value in _OPENERS) or tok.kind == TPL_HEAD:
                k = self.close_of(k) + 1
                continue
            if tok.kind == PUNCT and tok.value == sep:
                if k > start:
                    pieces.append((start, k))
                start = k + 1
            k += 1
        if min(k, hi) > start:
            pieces.append((start, min(k, hi)))
        return pieces

    def expr_end(self, lo: int, *, comma: bool = True) -> int:
        """Where the expression starting at ``lo`` ends: ``;``, a top-level ``,``, an enclosing closer, or ASI.

        Every top-level position the scan passes has the same end, so all of them are memoized; chained
        assignments (``a = b = c = ...``) stay linear.
        """
        memo = self._ends_comma if comma else self._ends
        toks = self.toks
        k = lo
        passed: list[int] = []
        end = self.n
        while k < self.n:
            if k in memo and k > lo:
                end = memo[k]
                break
            tok = toks[k]
            kind = tok.kind
            if (kind == PUNCT and tok.value in _OPENERS) or kind == TPL_HEAD:
                passed.append(k)
                k = self.close_of(k) + 1
                continue
            if (
                kind in (TPL_MID, TPL_TAIL)
                or (kind == PUNCT and (tok.value in _CLOSERS or tok.value == ";"))
                or (comma and is_punct(tok, ","))
                or (
                    k > lo and tok.line > toks[k - 1].end_line and _ends_operand(toks[k - 1]) and _starts_statement(tok)
                )
            ):
                end = k
                break
            passed.append(k)
            k += 1
        for position in passed:
            memo[position] = end
        return end

    # ----- chains and calls

    def chain_before(self, end: int) -> Chain | None:
        """The member chain whose last token is ``end`` (a name, ``)`` or ``]``), read backwards."""
        toks = self.toks
        segs: list[Seg] = []
        k = end
        while k >= 0:
            tok = toks[k]
            if tok.kind == NAME:
                segs.append(Seg("name", tok.value, k))
                if k >= 1 and is_punct(toks[k - 1], ".", "?."):
                    k -= 2
                    continue
                break
            if is_punct(tok, ")", "]"):
                opener = self.match[k]
                if opener < 0 or opener >= k:
                    return None
                if tok.value == ")":
                    segs.append(Seg("call", "", opener))
                else:
                    key = toks[opener + 1] if opener + 2 == k else None
                    segs.append(Seg("index", key.value if key is not None and key.kind == STR else "", opener))
                k = opener - 1
                if k >= 0 and is_punct(toks[k], "?."):
                    k -= 1
                if k >= 0 and (toks[k].kind == NAME or is_punct(toks[k], ")", "]")) and toks[k].value not in _CONTROL:
                    continue
                break
            break
        if not segs:
            return None
        segs.reverse()
        return Chain(tuple(segs), segs[0].index, end + 1)

    def chain_after(self, start: int, limit: int | None = None) -> Chain:
        """The member chain starting at the name ``start`` and ending before ``limit``: ``.x``, ``?.x``,
        ``(...)``, ``[...]``, a non-null ``!``."""
        toks = self.toks
        segs = [Seg("name", toks[start].value, start)]
        k = start + 1
        stop = self.n if limit is None else min(limit, self.n)
        while k < stop:
            tok = toks[k]
            if is_punct(tok, ".", "?.") and k + 1 < self.n and toks[k + 1].kind == NAME:
                segs.append(Seg("name", toks[k + 1].value, k + 1))
                k += 2
            elif is_punct(tok, "?.") and k + 1 < self.n and is_punct(toks[k + 1], "(", "["):
                k += 1
            elif is_punct(tok, "("):
                segs.append(Seg("call", "", k))
                k = self.close_of(k) + 1
            elif is_punct(tok, "["):
                close = self.close_of(k)
                key = toks[k + 1] if k + 2 == close else None
                segs.append(Seg("index", key.value if key is not None and key.kind == STR else "", k))
                k = close + 1
            elif is_punct(tok, "!") and k + 1 < self.n and is_punct(toks[k + 1], ".", "?.", "[", "(", ")"):
                k += 1
            elif tok.kind in (TPL, TPL_HEAD) and segs[-1].kind == "name":  # tagged template
                segs.append(Seg("call", "", k))
                k = (self.close_of(k) if tok.kind == TPL_HEAD else k) + 1
            else:
                break
        return Chain(tuple(segs), start, k)

    def qualname(self, chain: Chain, upto: int | None = None) -> str | None:
        """``module.export...`` or ``global.member...`` for the chain's leading names, or None."""
        segs = list(chain.segs[:upto] if upto is not None else chain.segs)
        if not segs or segs[0].kind != "name":
            return None
        first = segs[0].value
        rest = segs[1:]
        if first == "require" and rest and rest[0].kind == "call":
            module = self.require_arg(rest[0].index)
            if module is None:
                return None
            base, rest = module_name(module), rest[1:]
        elif first in self.aliases:
            base = self.aliases[first]
        elif first in _GLOBAL_OBJECTS and rest and rest[0].kind == "name" and rest[0].value not in self.declared:
            base, rest = rest[0].value, rest[1:]
        elif first in GLOBALS and first not in self.declared:
            base = first
        else:
            return None
        names = [base]
        for seg in rest:
            if seg.kind != "name":
                return None
            names.append(seg.value)
        qualified = ".".join(names)
        return qualified.replace("fs.promises.", "fs.")

    def require_arg(self, open_: int) -> str | None:
        toks = self.toks
        if open_ + 2 < self.n and toks[open_ + 1].kind in (STR, TPL) and is_punct(toks[open_ + 2], ")"):
            return toks[open_ + 1].value
        return None

    def _calls(self) -> Iterator[Call]:
        toks = self.toks
        for p, tok in enumerate(toks):
            if not is_punct(tok, "(") or p == 0:
                continue
            end = p - 1
            if is_punct(toks[end], "?."):
                end -= 1
            if is_punct(toks[end], ">"):
                end = self._generic_start(end)
            if end < 0 or not (toks[end].kind == NAME or is_punct(toks[end], ")", "]")):
                continue
            if toks[end].kind == NAME and toks[end].value in _NOT_CALLEE:
                continue
            close = self.close_of(p)
            after = toks[close + 1] if close + 1 < self.n else None
            if after is not None and is_punct(after, "{", "=>"):
                continue  # a definition: f(x) { ... } or an arrow's parameters
            callee = self.chain_before(end)
            if callee is None or self._is_definition(callee, after):
                continue
            yield Call(callee, p, tuple(self.split(p + 1, close)))

    def _generic_start(self, gt: int) -> int:
        """For ``f<T>(``, the index of ``f``; -1 when ``gt`` does not close a short type-argument list."""
        depth = 0
        toks = self.toks
        for k in range(gt, max(-1, gt - 30), -1):
            tok = toks[k]
            if is_punct(tok, ">"):
                depth += 1
            elif is_punct(tok, ">>"):
                depth += 2
            elif is_punct(tok, "<"):
                depth -= 1
                if depth == 0:
                    return k - 1 if k >= 1 and toks[k - 1].kind == NAME else -1
            elif not (
                tok.kind in (NAME, STR, NUM) or is_punct(tok, ".", ",", "|", "&", "[", "]", "{", "}", ":", ";", "?")
            ):
                return -1
        return -1

    def _is_definition(self, callee: Chain, after: Token | None) -> bool:
        """``function f(...)``, or a method with a TypeScript return type: ``m(x): T {``."""
        start = callee.start
        before = self.toks[start - 1] if start > 0 else None
        if before is not None and before.kind == NAME and before.value == "function":
            return True
        if after is not None and is_punct(after, ":") and len(callee.segs) == 1:
            return before is None or is_punct(before, "{", "}", ";") or before.value in _MODIFIERS
        return False

    # ----- scopes

    def _find_scopes(self) -> None:
        toks = self.toks
        open_scopes: list[int] = [0]
        for i, tok in enumerate(toks):
            while len(open_scopes) > 1 and self.scopes[open_scopes[-1]].close < i:
                open_scopes.pop()
            if is_punct(tok, "{") and (head := self._function_head(i)) is not None:
                start, params, name = head
                scope = Scope(len(self.scopes), i, self.close_of(i), open_scopes[-1], name)
                self.scopes.append(scope)
                open_scopes.append(scope.id)
                self._function_params(start, scope.id, params)
            elif is_punct(tok, "=>") and not (i + 1 < self.n and is_punct(toks[i + 1], "{")):
                arrow = self._arrow_head(i)
                if arrow is not None:  # an expression-bodied arrow: its parameters live in the enclosing scope
                    self._function_params(arrow[0], open_scopes[-1], arrow[1])
            self.scope_of[i] = open_scopes[-1]

    def _function_head(self, brace: int) -> tuple[int, list[str], str] | None:
        """(first token of the function, parameter names, name) when the ``{`` at ``brace`` opens a body."""
        toks = self.toks
        prev = brace - 1
        if prev < 0:
            return None
        if is_punct(toks[prev], "=>"):
            arrow = self._arrow_head(prev)
            return (arrow[0], arrow[1], self._assigned_name(arrow[0])) if arrow is not None else None
        if is_punct(toks[prev], ")"):
            close: int | None = prev
        elif toks[prev].kind == NAME or is_punct(toks[prev], ">", "]"):
            close = self._return_type_paren(prev)
        else:
            close = None
        if close is None:
            return None
        open_ = self.match[close]
        if open_ < 0 or open_ >= close:
            return None
        k = open_ - 1
        if k >= 0 and is_punct(toks[k], ">"):
            k = self._generic_start(k)
        if k < 0:
            return None
        before = toks[k]
        params = self._param_names(open_, close)
        if before.kind == NAME:
            if before.value in _CONTROL:
                return None
            if before.value == "function":
                return k, params, self._assigned_name(k)
            start = k - 1 if k >= 1 and toks[k - 1].kind == NAME and toks[k - 1].value == "function" else k
            if k >= 1 and is_punct(toks[k - 1], ".", "?."):
                return None  # a call such as obj.method(x) followed by a block
            return start, params, before.value
        if is_punct(before, "*") and k >= 1 and toks[k - 1].value == "function":
            return k - 1, params, self._assigned_name(k - 1)
        return None

    def _assigned_name(self, start: int) -> str:
        """``const make = () => ...``: the name a function expression is assigned to, if any."""
        toks = self.toks
        k = start - 1
        if k >= 0 and toks[k].kind == NAME and toks[k].value == "async":
            k -= 1
        if k >= 1 and is_punct(toks[k], "=", ":") and toks[k - 1].kind == NAME:
            return toks[k - 1].value
        return ""

    def _arrow_head(self, arrow: int) -> tuple[int, list[str]] | None:
        toks = self.toks
        k = arrow - 1
        if k < 0:
            return None
        if toks[k].kind == NAME and not (k >= 1 and is_punct(toks[k - 1], ":")):
            start = k - 1 if k >= 1 and toks[k - 1].value == "async" else k
            return start, [toks[k].value]
        close = k if is_punct(toks[k], ")") else self._return_type_paren(k)
        if close is None:
            return None
        open_ = self.match[close]
        if open_ < 0 or open_ >= close:
            return None
        start = open_
        if start >= 1 and is_punct(toks[start - 1], ">"):
            generic = self._generic_start(start - 1)
            start = generic + 1 if generic >= -1 else start
        if start >= 1 and toks[start - 1].kind == NAME and toks[start - 1].value == "async":
            start -= 1
        return start, self._param_names(open_, close)

    def _return_type_paren(self, k: int) -> int | None:
        """For ``(...): Type {`` or ``(...): Type =>``, the ``)`` before the annotation."""
        toks = self.toks
        for j in range(k, max(-1, k - 40), -1):
            tok = toks[j]
            if is_punct(tok, ":") and j >= 1 and is_punct(toks[j - 1], ")"):
                return j - 1
            if is_punct(tok, ";", "{", "}", "=", "=>") or (tok.kind == NAME and tok.value in _DECLARE):
                return None
        return None

    def _param_names(self, open_: int, close: int) -> list[str]:
        toks = self.toks
        names: list[str] = []
        for lo, hi in self.split(open_ + 1, close):
            k = self._skip_decorators(lo, hi)[0]
            while k < hi and (is_punct(toks[k], "...") or (toks[k].kind == NAME and toks[k].value in _MODIFIERS)):
                k += 1
            if k >= hi:
                continue
            if is_punct(toks[k], "{", "["):
                names.extend(name for name, _ in self._pattern_names(k))
            elif toks[k].kind == NAME:
                names.append(toks[k].value)
        return names

    def _pattern_names(self, open_: int) -> list[tuple[str, int]]:
        """(name, token index) bound by a destructuring pattern ``{a, b: c, d = 1, ...e}`` or ``[a, , b]``."""
        toks = self.toks
        close = self.close_of(open_)
        names = []
        for k in range(open_ + 1, min(close, self.n - 1)):
            tok = toks[k]
            if tok.kind != NAME:
                continue
            nxt, prev = toks[k + 1], toks[k - 1]
            if is_punct(nxt, ":") or is_punct(prev, "=", ".", "?."):
                continue
            if is_punct(nxt, ",", "}", "]", "=") or k + 1 == close:
                names.append((tok.value, k))
        return names

    def _skip_decorators(self, lo: int, hi: int) -> tuple[int, list[tuple[str, bool]]]:
        """Past the decorators ``@Name`` and ``@Name(args)`` at ``lo``: (index, [(name, takes a Parse*Pipe), ...])."""
        toks = self.toks
        found: list[tuple[str, bool]] = []
        k = lo
        while k + 1 < hi and is_punct(toks[k], "@") and toks[k + 1].kind == NAME:
            name = toks[k + 1].value
            k += 2
            while k + 1 < hi and is_punct(toks[k], ".") and toks[k + 1].kind == NAME:
                name, k = toks[k + 1].value, k + 2
            piped = False
            if k < hi and is_punct(toks[k], "("):
                close = self.close_of(k)
                piped = any(
                    t.kind == NAME and t.value.startswith("Parse") and t.value.endswith("Pipe") for t in toks[k:close]
                )
                k = close + 1
            found.append((name, piped))
        return k, found

    def _framework_params(self, start: int, scope: int) -> None:
        """Register request-carrying parameters: NestJS decorated ones, Next.js ``params``, a server action's FormData."""
        toks = self.toks
        open_ = next((j for j in range(start, min(start + 12, self.n)) if is_punct(toks[j], "(")), None)
        if open_ is None or self.match[open_] < 0:
            return
        close = self.match[open_]
        for lo, hi in self.split(open_ + 1, close):
            k, decorators = self._skip_decorators(lo, hi)
            while k < hi and toks[k].kind == NAME and toks[k].value in _MODIFIERS:
                k += 1
            if k >= hi:
                continue
            if is_punct(toks[k], "{"):
                names = [name for name, _ in self._pattern_names(k)]
                annotated = ""
            elif toks[k].kind == NAME:
                names = [toks[k].value]
                colon = k + 2 if k + 1 < hi and is_punct(toks[k + 1], "?") else k + 1
                annotated = toks[colon + 1].value if colon + 1 < hi and is_punct(toks[colon], ":") else ""
            else:
                continue
            label = next((_NEST_SOURCES[d] for d, piped in decorators if d in _NEST_SOURCES and not piped), None)
            if label is not None and annotated not in ("number", "boolean"):
                for name in names:
                    self.source_params[(scope, name)] = f"{label} parameter"
            elif self.next_context:
                for name in names:
                    if name in _NEXT_PARAMS:
                        self.source_params[(scope, name)] = f"Next.js {name}"
                    elif self._use_server and (name in _FORM_PARAMS or annotated == "FormData"):
                        self.source_params[(scope, name)] = "Next.js server action FormData"

    def _function_params(self, start: int, scope: int, params: list[str]) -> None:
        self.params.update(params)
        self.declared.update(params)
        for name in params:
            self._bind(scope, Binding(name, start, start, start, "param"))
        self._framework_params(start, scope)
        if not params:
            return
        toks = self.toks
        before = toks[start - 1] if start > 0 else None
        if before is None:
            return
        if is_punct(before, "=") and start >= 2 and toks[start - 2].value == "onmessage":
            self.message_params.add((scope, params[0]))
            return
        call_open = self.parent[start]
        if call_open < 1 or not is_punct(toks[call_open], "("):
            return
        callee = self.chain_before(call_open - 1)
        if callee is None or callee.segs[-1].kind != "name":
            return
        method = callee.segs[-1].value
        first_arg = call_open + 1
        if method == "addEventListener" and is_punct(before, ","):
            if toks[first_arg].kind == STR and toks[first_arg].value == "message":
                self.message_params.add((scope, params[0]))
        elif method in _ITER_METHODS and start == first_arg and len(callee.segs) >= 2:
            dot = callee.segs[-1].index - 1
            self._bind(scope, Binding(params[0], start, callee.start, dot, "iter"))

    def scope_chain(self, at: int) -> Iterator[int]:
        sid: int | None = self.scope_of[at] if 0 <= at < self.n else 0
        while sid is not None:
            yield sid
            sid = self.scopes[sid].parent

    # ----- bindings

    def _bind(self, scope: int, binding: Binding) -> None:
        self._bound.add(binding.pos)
        self.bindings.setdefault((scope, binding.name), []).append(binding)

    def _collect_bindings(self) -> None:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind != NAME:
                continue
            after_dot = i > 0 and is_punct(toks[i - 1], ".", "?.")
            if after_dot:
                continue
            if tok.value in _DECLARE:
                self._declaration(i)
            elif tok.value in ("function", "class") and i + 1 < self.n and toks[i + 1].kind == NAME:
                name = toks[i + 1].value
                self.declared.add(name)
                self._bind(self.scope_of[i], Binding(name, i + 1, i + 1, i + 1, "decl"))
            elif (
                i not in self._bound
                and i + 1 < self.n
                and toks[i + 1].kind == PUNCT
                and toks[i + 1].value in _ASSIGN_OPS
            ):
                if i > 0 and is_punct(toks[i - 1], "{", ",", "(", "[") and self._in_pattern(i):
                    continue  # a default value in a destructuring pattern or a parameter list
                hi = self.expr_end(i + 2, comma=False)
                self._bind(self.scope_of[i], Binding(tok.value, i, i + 2, hi, "value"))

    def _in_pattern(self, i: int) -> bool:
        """True when the name at ``i`` sits directly in an object/array literal, a pattern or a parameter list."""
        opener = self.parent[i]
        if opener < 0:
            return False
        if is_punct(self.toks[opener], "(", "["):
            return True
        before = self.toks[opener - 1] if opener > 0 else None
        if before is None:
            return False
        return is_punct(before, "(", ",", "=", ":", "[", "?", "||", "&&", "??") or (
            before.kind == NAME and before.value in (*_DECLARE, "return")
        )

    def _declaration(self, i: int) -> None:
        toks = self.toks
        scope = self.scope_of[i]
        k = i + 1
        while k < self.n:
            tok = toks[k]
            if tok.kind == NAME:
                names, pat_end = [(tok.value, k)], k + 1
            elif is_punct(tok, "{", "["):
                names, pat_end = self._pattern_names(k), self.close_of(k) + 1
            else:
                return
            self.declared.update(name for name, _ in names)
            j = pat_end
            if j < self.n and is_punct(toks[j], "!"):
                j += 1
            if j < self.n and is_punct(toks[j], ":"):  # a TypeScript annotation
                j = self._skip_type(j + 1)
            if j < self.n and toks[j].kind == NAME and toks[j].value in ("of", "in"):
                close = self.close_of(self.parent[i]) if self.parent[i] >= 0 else self.expr_end(j + 1)
                for name, pos in names:
                    self._bind(scope, Binding(name, pos, j + 1, close, "iter"))
                return
            if j < self.n and is_punct(toks[j], "="):
                hi = self.expr_end(j + 1)
                for name, pos in names:
                    self._bind(scope, Binding(name, pos, j + 1, hi, "value"))
                if is_punct(tok, "{"):
                    self._destructured_require(k, j + 1, hi)
                j = hi
            else:
                for name, pos in names:
                    self._bind(scope, Binding(name, pos, pos, pos, "decl"))
            if j < self.n and is_punct(toks[j], ","):
                k = j + 1
                continue
            return

    def _skip_type(self, k: int) -> int:
        """The index of the ``=``, ``,``, ``;`` or ``of``/``in`` that ends a type annotation starting at ``k``."""
        toks = self.toks
        angle = 0
        while k < self.n:
            tok = toks[k]
            if is_punct(tok, "(", "[", "{"):
                k = self.close_of(k) + 1
                continue
            if is_punct(tok, "<"):
                angle += 1
            elif is_punct(tok, ">"):
                angle -= 1
            elif is_punct(tok, ">>"):
                angle -= 2
            elif is_punct(tok, "}", "]") or (
                angle <= 0 and (is_punct(tok, "=", ",", ";", ")") or (tok.kind == NAME and tok.value in ("of", "in")))
            ):
                return k
            k += 1
        return k

    def lookup(self, name: str, at: int) -> list[Binding] | None:
        """Bindings of ``name`` visible at token ``at`` (those before it in the innermost scope binding it)."""
        for sid in self.scope_chain(at):
            found = self.bindings.get((sid, name))
            if found:
                before = [b for b in found if b.pos < at]
                return before or None
        return None

    # ----- module aliases

    def _collect_aliases(self) -> None:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind == NAME and tok.value == "import" and not (i > 0 and is_punct(toks[i - 1], ".")):
                self._import(i)
        for _ in range(4):  # copies of copies: const cp = require('x'); const run = cp.exec
            changed = False
            for (_, name), found in self.bindings.items():
                if name in self.aliases or len(found) != 1 or found[0].kind != "value":
                    continue
                target = self._alias_target(found[0])
                if target is not None:
                    self.aliases[name] = target
                    changed = True
            if not changed:
                break

    def _import(self, i: int) -> None:
        toks = self.toks
        k = i + 1
        if k < self.n and toks[k].kind == NAME and toks[k].value == "type":
            return
        if k < self.n and is_punct(toks[k], "("):
            return  # dynamic import, handled as a binding value
        end = k
        while (
            end < self.n and not (toks[end].kind == NAME and toks[end].value == "from") and not is_punct(toks[end], ";")
        ):
            if toks[end].kind == STR:
                break
            end += 1
        if end + 1 >= self.n or toks[end].kind != NAME or toks[end + 1].kind != STR:
            if k < self.n and toks[k].kind == STR:
                self.modules.add(module_name(toks[k].value))
            return
        module = module_name(toks[end + 1].value)
        self.modules.add(module)
        j = k
        while j < end:
            tok = toks[j]
            if is_punct(tok, "*") and j + 2 < end and toks[j + 1].value == "as":
                self._alias(toks[j + 2].value, module)
                j += 3
            elif tok.kind == NAME and tok.value != "type":
                self._alias(tok.value, module)
                j += 1
            elif is_punct(tok, "{"):
                close = min(self.close_of(j), end)
                for lo, hi in self.split(j + 1, close):
                    parts = [t for t in toks[lo:hi] if t.kind in (NAME, STR) and t.value != "type"]
                    if len(parts) == 3 and parts[1].value == "as":
                        self._alias(parts[2].value, f"{module}.{parts[0].value}")
                    elif len(parts) == 1:
                        self._alias(parts[0].value, f"{module}.{parts[0].value}")
                j = close + 1
            else:
                j += 1

    def _alias(self, name: str, target: str) -> None:
        self.aliases[name] = target.removesuffix(".default")
        self.declared.add(name)

    def _alias_target(self, binding: Binding) -> str | None:
        """What a simple binding's value resolves to: a module, a module member, or a promisified one."""
        toks = self.toks
        lo, hi = binding.lo, binding.hi
        while lo < hi and toks[lo].kind == NAME and toks[lo].value == "await":
            lo += 1
        if lo >= hi or toks[lo].kind != NAME:
            return None
        if toks[lo].value == "import" and lo + 1 < hi and is_punct(toks[lo + 1], "("):
            module = self.require_arg(lo + 1)
            if module is None or self.close_of(lo + 1) + 1 != hi:
                return None
            self.modules.add(module_name(module))
            return module_name(module)
        chain = self.chain_after(lo)
        if chain.end != hi:
            return None
        segs = chain.segs
        if len(segs) >= 2 and segs[-1].kind == "call" and segs[-2].kind == "name" and segs[-2].value == "promisify":
            arg = segs[-1].index + 1
            if toks[arg].kind == NAME:
                inner = self.chain_after(arg)
                if inner.end == self.close_of(segs[-1].index):
                    return self.qualname(inner)
            return None
        if segs[0].value == "require":
            if len(segs) < 2 or segs[1].kind != "call" or (module := self.require_arg(segs[1].index)) is None:
                return None
            self.modules.add(module_name(module))
            return self.qualname(chain)
        if segs[0].value in self.aliases and len(segs) >= 2:
            return self.qualname(chain)
        return None

    def _destructured_require(self, pattern: int, lo: int, hi: int) -> None:
        """``const { exec, execSync: run } = require('child_process')``, also ``= await import(...)``."""
        toks = self.toks
        while lo < hi and toks[lo].kind == NAME and toks[lo].value == "await":
            lo += 1
        if lo + 1 >= hi or toks[lo].kind != NAME or toks[lo].value not in ("require", "import"):
            return
        module = self.require_arg(lo + 1)
        if module is None or self.close_of(lo + 1) + 1 != hi:
            return
        base = module_name(module)
        self.modules.add(base)
        for a, b in self.split(pattern + 1, self.close_of(pattern)):
            parts = toks[a:b]
            if len(parts) >= 3 and parts[0].kind in (NAME, STR) and is_punct(parts[1], ":") and parts[2].kind == NAME:
                self._alias(parts[2].value, f"{base}.{parts[0].value}")
            elif parts and parts[0].kind == NAME:
                self._alias(parts[0].value, f"{base}.{parts[0].value}")

    # ----- literals

    def literal(self, lo: int, hi: int, depth: int = 0) -> bool:
        """True for strings, numbers, templates without non-literal parts and names bound only to literals."""
        if lo >= hi or depth > MAX_DEPTH:
            return False
        toks = self.toks
        k = lo
        while k < hi:
            tok = toks[k]
            kind = tok.kind
            if kind in (STR, NUM, TPL, REGEX) or (kind == NAME and tok.value in ("true", "false", "null", "undefined")):
                k += 1
            elif kind == TPL_HEAD:
                if not all(self.literal(a, b, depth + 1) for a, b in self.template_exprs(k)):
                    return False
                k = self.close_of(k) + 1
            elif kind == NAME:
                if (k + 1 < hi and is_punct(toks[k + 1], ".", "?.", "(", "[")) or tok.value in ("as", "satisfies"):
                    return False
                if not self._literal_name(tok.value, k, depth):
                    return False
                k += 1
            elif is_punct(tok, "(", "["):
                close = self.close_of(k)
                if not all(self.literal(a, b, depth + 1) for a, b in self.split(k + 1, close)):
                    return False
                k = close + 1
            elif is_punct(tok, "+", "-"):
                k += 1
            else:
                return False
        return True

    def _literal_name(self, name: str, at: int, depth: int) -> bool:
        if depth >= MAX_HOPS:
            return False
        found = self.lookup(name, at)
        if not found:
            return False
        return all(b.kind == "value" and self.literal(b.lo, b.hi, depth + 1) for b in found)

    def string_value(self, lo: int, hi: int) -> str | None:
        """The text of a single string or template-without-substitution token."""
        if hi == lo + 1 and self.toks[lo].kind in (STR, TPL):
            return self.toks[lo].value
        return None

    def built_string(self, lo: int, hi: int, depth: int = 0) -> tuple[bool, str]:
        """(built from a non-literal part, the literal text) for a template or a ``+`` concatenation."""
        if lo >= hi or depth > MAX_DEPTH:
            return False, ""
        toks = self.toks
        pieces = self.split(lo, hi, "+")
        if len(pieces) == 1:
            a, b = pieces[0]
            tok = toks[a]
            if tok.kind == TPL_HEAD and self.close_of(a) + 1 == b and not self.tagged(a):
                texts, dynamic = [], False
                parts = self.tpl_parts.get(a, [a])
                for idx, (x, y) in enumerate(self.template_exprs(a)):
                    texts.append(toks[parts[idx]].value)
                    texts.append(" ? ")
                    dynamic = dynamic or not self.literal(x, y, depth + 1)
                texts.append(toks[parts[-1]].value)
                return dynamic, "".join(texts)
            if tok.kind == NAME and b == a + 1 and depth < MAX_HOPS:
                for binding in self.lookup(tok.value, a) or ():
                    if binding.kind == "value" and (built := self.built_string(binding.lo, binding.hi, depth + 1))[0]:
                        return built
                return False, ""
            if is_punct(tok, "(") and self.close_of(a) + 1 == b:
                return self.built_string(a + 1, b - 1, depth + 1)
            return False, ""
        dynamic, has_string, texts = False, False, []
        for a, b in pieces:
            text = self.string_value(a, b)
            if text is not None:
                texts.append(text)
                has_string = True
                continue
            inner, inner_text = self.built_string(a, b, depth + 1)
            if not inner_text and b == a + 1 and toks[a].kind == NAME:
                inner_text = self._literal_text(toks[a].value, a)
            if inner_text:
                has_string = True
                texts.append(inner_text)
            else:
                texts.append(" ? ")
            dynamic = dynamic or inner or not self.literal(a, b, depth + 1)
        return dynamic and has_string, "".join(texts)

    def _literal_text(self, name: str, at: int) -> str:
        found = self.lookup(name, at) or []
        if len(found) == 1 and found[0].kind == "value":
            return self.string_value(found[0].lo, found[0].hi) or ""
        return ""

    def tagged(self, tpl: int) -> bool:
        if tpl == 0:
            return False
        prev = self.toks[tpl - 1]
        return (prev.kind == NAME and prev.value not in _NOT_OPERAND) or is_punct(prev, ")", "]")

    # ----- object literals

    def object_entries(self, lo: int, hi: int, depth: int = 0) -> dict[str, tuple[int, int]] | None:
        """``key -> value span`` of an object literal span (or a name bound to one), else None."""
        toks = self.toks
        if hi == lo + 1 and toks[lo].kind == NAME and depth < MAX_HOPS:
            found = self.lookup(toks[lo].value, lo)
            if found and len(found) == 1 and found[0].kind == "value":
                return self.object_entries(found[0].lo, found[0].hi, depth + 1)
            return None
        if lo >= hi or not is_punct(toks[lo], "{") or self.close_of(lo) + 1 != hi:
            return None
        entries: dict[str, tuple[int, int]] = {}
        for a, b in self.split(lo + 1, hi - 1):
            key = toks[a]
            if key.kind in (NAME, STR) and a + 1 < b and is_punct(toks[a + 1], ":"):
                entries[key.value] = (a + 2, b)
            elif key.kind == NAME and b == a + 1:
                entries[key.value] = (a, b)
        return entries

    # ----- taint

    def taint(self, lo: int, hi: int, depth: int = 0) -> list[Origin]:
        """Origins of tainted data that can reach the value of ``lo:hi``."""
        if lo >= hi or depth > MAX_DEPTH:
            return []
        key = (lo, hi)
        if key in self._memo:
            return self._memo[key]
        if key in self._active:
            return []
        self._active.add(key)
        try:
            result = self._taint_span(lo, hi, depth)
        finally:
            self._active.discard(key)
        self._memo[key] = result
        return result

    def _taint_span(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        while lo < hi and toks[lo].kind == NAME and toks[lo].value in ("await", "yield"):
            lo += 1
        while lo < hi and is_punct(toks[lo], "..."):
            lo += 1
        if lo >= hi:
            return []
        # TypeScript casts and annotations end the value: x as string, x satisfies T
        k = lo
        top: list[int] = []
        while k < hi:
            tok = toks[k]
            if (tok.kind == PUNCT and tok.value in _OPENERS) or tok.kind == TPL_HEAD:
                k = self.close_of(k) + 1
                continue
            if tok.kind == NAME and tok.value in ("as", "satisfies") and k > lo:
                hi = k
                break
            if tok.kind == PUNCT and not (tok.value == "!" and k > lo and _ends_operand(toks[k - 1])):
                top.append(k)  # a '!' after an operand is TypeScript's non-null assertion, not a negation
            k += 1
        ops = [toks[k].value for k in top if k < hi]
        if "=>" in ops:
            return []
        if "?" in ops:
            question = next(k for k in top if toks[k].value == "?")
            colon = self._ternary_colon(question, hi)
            if colon is None:
                return []
            return _add(self.taint(question + 1, colon, depth + 1), self.taint(colon + 1, hi, depth + 1))
        if any(op in ("===", "==", "!==", "!=", "<", ">", "<=", ">=", "!", "~") for op in ops):
            return []
        if any(op in ("=", "+=", "||=", "??=") for op in ops):
            eq = next(k for k in top if toks[k].value in ("=", "+=", "||=", "??="))
            return self.taint(eq + 1, hi, depth + 1)
        if toks[lo].kind == NAME and toks[lo].value in ("typeof", "void", "delete", "function", "class"):
            return []
        if "+" not in ops and any(op in ("-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>", ">>>") for op in ops):
            return []
        origins: list[Origin] = []
        for a, b in self._terms(lo, hi, top):
            origins = _add(origins, self._term(a, b, depth))
        cleared = self._prefix_cleared(lo, hi)
        if cleared:
            origins = [Origin(o.kind, o.label, o.trace, o.cleared | cleared) for o in origins]
        return origins

    def _terms(self, lo: int, hi: int, top: list[int]) -> list[tuple[int, int]]:
        cuts = [k for k in top if lo <= k < hi and self.toks[k].value in ("+", "||", "??", "&&", ",")]
        terms, start = [], lo
        for cut in cuts:
            if cut > start:
                terms.append((start, cut))
            start = cut + 1
        if hi > start:
            terms.append((start, hi))
        return terms

    def _ternary_colon(self, question: int, hi: int) -> int | None:
        depth = 0
        k = question + 1
        while k < hi:
            tok = self.toks[k]
            if (tok.kind == PUNCT and tok.value in _OPENERS) or tok.kind == TPL_HEAD:
                k = self.close_of(k) + 1
                continue
            if is_punct(tok, "?"):
                depth += 1
            elif is_punct(tok, ":"):
                if depth == 0:
                    return k
                depth -= 1
            k += 1
        return None

    def _prefix_cleared(self, lo: int, hi: int) -> frozenset[str]:
        """URL and redirect classes a literal start of the string fixes (scheme and host, or a local path)."""
        tok = self.toks[lo]
        if tok.kind not in (STR, TPL, TPL_HEAD) or (tok.kind == TPL_HEAD and self.tagged(lo)):
            return frozenset()
        if _FIXED_HOST.match(tok.value):
            return frozenset({URL, REDIRECT})
        if _LOCAL_PATH.match(tok.value):
            return frozenset({REDIRECT})
        return frozenset()

    def _term(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        while lo < hi and ((toks[lo].kind == NAME and toks[lo].value in ("await", "new")) or is_punct(toks[lo], "...")):
            lo += 1
        if lo >= hi:
            return []
        tok = toks[lo]
        if tok.kind == TPL_HEAD and not self.tagged(lo):
            origins: list[Origin] = []
            for a, b in self.template_exprs(lo):
                origins = _add(origins, self.taint(a, b, depth + 1))
            return origins
        if tok.kind in (STR, NUM, TPL, REGEX, JSX):
            return []
        if is_punct(tok, "(", "["):
            close = self.close_of(lo)
            origins = []
            for a, b in self.split(lo + 1, close):
                origins = _add(origins, self.taint(a, b, depth + 1))
            return self._postfix(origins, close + 1, hi) if tok.value == "(" else origins
        if is_punct(tok, "{"):
            origins = []
            for a, b in self.split(lo + 1, self.close_of(lo)):
                colon = next((k for k in range(a, b) if is_punct(toks[k], ":")), None)
                origins = _add(origins, self.taint(colon + 1 if colon is not None else a, b, depth + 1))
            return origins
        if tok.kind != NAME:
            return []
        chain = self.chain_after(lo, hi)
        source = self._source(chain)
        if source is not None:
            origin, used = source
            return self._postfix([origin], self._seg_end(chain.segs[used - 1]), hi)
        return self._call_or_name(chain, hi, depth)

    def _seg_end(self, seg: Seg) -> int:
        return seg.index + 1 if seg.kind == "name" else self.close_of(seg.index) + 1

    def _postfix(self, origins: list[Origin], k: int, hi: int) -> list[Origin]:
        """Keep the origins through ``.x``, ``[i]`` and string/array method calls; another call drops them."""
        toks = self.toks
        last_name = ""
        while k < hi and origins:
            tok = toks[k]
            if is_punct(tok, ".", "?.") and k + 1 < hi and toks[k + 1].kind == NAME:
                last_name = toks[k + 1].value
                k += 2
            elif is_punct(tok, "["):
                k = self.close_of(k) + 1
            elif is_punct(tok, "("):
                if last_name not in _PROPAGATE_METHODS:
                    return []
                k = self.close_of(k) + 1
            elif is_punct(tok, "!", "?."):
                k += 1
            else:
                break
        return origins

    def _call_or_name(self, chain: Chain, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        segs = chain.segs
        first_call = next((n for n, seg in enumerate(segs) if seg.kind == "call"), None)
        if first_call is None:
            return self._name(segs[0].value, segs[0].index, chain, hi, depth)
        callee = Chain(segs[:first_call], chain.start, segs[first_call].index)
        name = self.qualname(callee)
        call_seg = segs[first_call]
        if toks[call_seg.index].kind in (TPL, TPL_HEAD):  # a tagged template
            return []
        args = self.split(call_seg.index + 1, self.close_of(call_seg.index))
        after = self._seg_end(call_seg)
        last = segs[first_call - 1].value if first_call >= 1 and segs[first_call - 1].kind == "name" else ""
        if name in _NUMERIC_CALLS or (name or "").startswith("Math."):
            return []
        if name in _PROPAGATE_CALLS or name in _CLEARING_CALLS:
            origins: list[Origin] = []
            if name == "URL" and len(args) >= 2:
                args = args[:1]  # new URL(input, base): the base only fills in a relative input
            for a, b in args:
                origins = _add(origins, self.taint(a, b, depth + 1))
            clear = _CLEARING_CALLS.get(name or "", frozenset())
            origins = [Origin(o.kind, o.label, o.trace, o.cleared | clear) for o in origins]
            return self._postfix(origins, after, hi)
        if last in _HTML_SANITIZER_NAMES and first_call >= 1:
            origins = []
            for a, b in args:
                origins = _add(origins, self.taint(a, b, depth + 1))
            return [Origin(o.kind, o.label, o.trace, o.cleared | {HTML}) for o in origins]
        if first_call >= 2 and last in _PROPAGATE_METHODS:
            receiver_end = segs[first_call - 1].index - 1  # the '.' before the method
            origins = self.taint(chain.start, receiver_end, depth + 1)
            return self._postfix(origins, after, hi)
        return []

    def _name(self, name: str, at: int, chain: Chain, hi: int, depth: int) -> list[Origin]:
        if depth >= MAX_DEPTH or name in ("this", "true", "false", "null", "undefined"):
            return []
        found = self.lookup(name, at)
        if not found:
            return []
        origins: list[Origin] = []
        for binding in found:
            if binding.kind not in ("value", "iter") or binding.lo >= binding.hi:
                continue
            for origin in self.taint(binding.lo, binding.hi, depth + 1):
                line = self.toks[binding.pos].line
                step = TraceStep(line, f"assigned to {name}")
                trace = (
                    origin.trace
                    if len(origin.trace) >= MAX_TRACE or origin.trace[-1] == step
                    else (*origin.trace, step)
                )
                origins = _add(origins, [Origin(origin.kind, origin.label, trace, origin.cleared)])
        return self._postfix(origins, at + 1, hi) if origins else []

    def _source(self, chain: Chain) -> tuple[Origin, int] | None:
        """(origin, number of chain links the source covers) when the chain starts with a taint source."""
        segs = chain.segs
        names = [seg.value if seg.kind == "name" else "()" if seg.kind == "call" else "[]" for seg in segs]
        first = names[0]
        line = self.toks[chain.start].line
        if self.source_params:
            for sid in self.scope_chain(chain.start):
                if (sid, first) in self.source_params:
                    return self._origin("request", self.source_params[(sid, first)], line), 1
                if (sid, first) in self.bindings:
                    break  # a nearer binding of the same name shadows the parameter
        if first in ("req", "request") and len(segs) >= 2 and first in self.params:
            if segs[1].kind == "name" and names[1] in _BODY_READERS and len(segs) >= 3 and segs[2].kind == "call":
                return self._origin("request", f"Request {first}.{names[1]}()", line), 3
            if segs[1].kind == "name" and names[1] in _REQUEST_FIELDS:
                return self._origin("request", f"Express {first}.{names[1]}", line), 2
            if segs[1].kind == "name" and names[1] in _REQUEST_CALLS and len(segs) >= 3 and segs[2].kind == "call":
                return self._origin("request", f"Express {first}.{names[1]}()", line), 3
        if (
            self.next_context
            and first == "context"
            and first in self.params
            and len(segs) >= 2
            and names[1] == "params"
        ):
            return self._origin("request", "Next.js route params", line), 2
        if first == "ctx" and len(segs) >= 2 and first in self.params and segs[1].kind == "name":
            if names[1] == "get" and len(segs) >= 3 and segs[2].kind == "call":
                return self._origin("request", "Koa ctx.get()", line), 3
            if names[1] in _KOA_FIELDS:
                return self._origin("request", f"Koa ctx.{names[1]}", line), 2
            if (
                names[1] == "request"
                and len(segs) >= 3
                and names[2] in ("query", "body", "url", "path", "files", "headers")
            ):
                return self._origin("request", f"Koa ctx.request.{names[2]}", line), 3
        dom = self._dom_source(chain, names)
        if dom is not None:
            label, used = dom
            return self._origin("dom", label, line), used
        if self.modules & _LLM_MODULES:
            for tail in _LLM_TAILS:
                size = len(tail)
                for n in range(size, len(segs)):
                    if segs[n].kind == "call" and tuple(names[n - size : n]) == tail:
                        return self._origin("llm", "LLM output (" + ".".join(tail) + ")", line), n + 1
        return None

    def _dom_source(self, chain: Chain, names: list[str]) -> tuple[str, int] | None:
        first = names[0]
        if first in self.declared:
            second = names[1] if len(names) >= 2 else ""
            if second == "data" and any((sid, first) in self.message_params for sid in self.scope_chain(chain.start)):
                return "postMessage event.data", 2
            if first in _ROUTER_HOOKS and second == "()" and self.aliases.get(first, "").startswith(_ROUTER_MODULES):
                return f"{'Next.js' if self.aliases[first].startswith('next/') else 'React Router'} {first}()", 2
            return None
        offset = 1 if first in _GLOBAL_OBJECTS and len(names) > 1 else 0
        head = names[offset]
        if head == "location" and (offset or head not in self.declared):
            return ("window.location" if offset else "location"), offset + 1
        if head == "name" and offset:
            return "window.name", 2
        if head == "document" and len(names) > offset + 1 and names[offset + 1] in _DOM_DOCUMENT:
            return f"document.{names[offset + 1]}", offset + 2
        return None

    def _origin(self, kind: str, label: str, line: int) -> Origin:
        return Origin(kind, label, (TraceStep(line, f"{label} (source)"),))


def _ends_operand(tok: Token) -> bool:
    if tok.kind == NAME:
        return tok.value not in _NOT_OPERAND
    if tok.kind == PUNCT:
        return tok.value in (")", "]", "}", "++", "--")
    return True


def _starts_statement(tok: Token) -> bool:
    return tok.kind in (NAME, NUM, STR, TPL, TPL_HEAD)
