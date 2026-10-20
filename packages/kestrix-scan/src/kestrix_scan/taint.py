# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Intraprocedural taint analysis over the standard-library AST.

Forward data flow over each function body, each class body and the module top level, separately.
Nothing crosses a function boundary: parameters start clean (except FastAPI route parameters), a
call to any function returns clean data unless it is a source, a sanitizer or on the short
propagate list, and nested functions and lambdas are analyzed as scopes of their own.

**Sources** carry a kind, which sets the finding's confidence and which rules may fire:

- ``request`` (high): Flask ``request.args/form/values/json/get_json()/files/headers/cookies/data``,
  Django ``request.GET/POST/body/headers/COOKIES/FILES/META`` on a name ``request`` that is not an
  import, and parameters of FastAPI ``@app.get/post/...`` and ``@router.*`` handlers that are
  unannotated or annotated as text (``str``, ``bytes``, ``Optional[str]``, ``list[str]`` ...). A
  parameter with a ``Depends``/``Security`` default or annotation, or any other type, is skipped;
  FastAPI validates numbers, UUIDs and models before the handler runs.
- ``llm`` (high): results of ``anthropic`` ``...messages.create(...)``, OpenAI
  ``...chat.completions.create(...)``/``...responses.create(...)``, ``litellm.completion``,
  ``ollama.chat``/``generate``, Google GenAI ``generate_content`` and LangChain ``invoke``, each
  only when the file imports that library. Attributes and items of the result stay tainted, so
  ``response.content[0].text`` is model output.
- ``cli`` (medium): ``input()`` and ``sys.argv``.
- ``env`` (low): ``os.environ.get``, ``os.getenv`` and ``os.environ[...]``.

**Propagation:** assignment (also tuple targets, walrus and ``for`` targets), augmented assignment,
f-strings, ``%``, ``+`` and other operators, ``str.format`` and the other ``str`` methods,
containers, subscripts, attribute access on tainted objects, ``dict.get``-style methods, ``await``,
comprehensions, and the calls ``str``, ``bytes``, ``"".join``, ``os.path.join`` and ``pathlib.Path``.
Branches are joined; loops run twice. A plain ``x = clean`` removes the taint of ``x``.

**Sanitizers** clear one sink class each and nothing else: ``shlex.quote`` (shell),
``os.path.basename`` and ``werkzeug.utils.secure_filename`` (path), ``html.escape`` and
``markupsafe.escape`` (html). ``int``, ``float`` and ``uuid.UUID`` return a number or an id, so their
result is clean for every class. A string whose literal start fixes the scheme and host
(``f"https://api.example.com/{x}"``) is clean for SSRF and redirects; one starting with a single
``/`` and a path character is clean for redirects. A path is clean for path sinks after
``os.path.realpath``/``abspath``/``normpath`` or ``Path.resolve()`` *and* a guard on the same
name: ``if not p.startswith(base)`` or ``if not p.is_relative_to(base)`` whose body raises, returns
or aborts, or the body of ``if p.is_relative_to(base):``, also as one operand of ``and`` (body) or
``or`` (the negated form). Other guards are not recognized.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from .models import Confidence, TraceStep

MAX_ORIGINS = 4  # distinct sources kept per value
MAX_TRACE = 8  # trace steps kept per source, the sink step not included
_MAX_DEPTH = 60  # bound on recursive expression evaluation
_LOOP_PASSES = 2

SQL, SHELL, CODE, PATH, HTML, TEMPLATE, URL, REDIRECT = (
    "sql",
    "shell",
    "code",
    "path",
    "html",
    "template",
    "url",
    "redirect",
)
_NORMALIZED = "normalized"  # marker: the path went through realpath/abspath/normpath/resolve

REMOTE_KINDS = frozenset({"request", "llm"})  # kinds that may fire the taint-only rules
CONFIDENCE: dict[str, Confidence] = {"request": "high", "llm": "high", "cli": "medium", "env": "low"}
_KIND_ORDER = {"llm": 0, "request": 1, "cli": 2, "env": 3}

_FLASK_SOURCES = frozenset({"args", "form", "values", "json", "get_json", "files", "headers", "cookies", "data"})
_DJANGO_SOURCES = frozenset({"GET", "POST", "body", "headers", "COOKIES", "FILES", "META"})
_ENV_CALLS = frozenset({"os.environ.get", "os.getenv"})
_CLEARING_CALLS: dict[str, frozenset[str]] = {
    "shlex.quote": frozenset({SHELL}),
    "pipes.quote": frozenset({SHELL}),
    "os.path.basename": frozenset({PATH}),
    "werkzeug.utils.secure_filename": frozenset({PATH}),
    "werkzeug.secure_filename": frozenset({PATH}),
    "html.escape": frozenset({HTML}),
    "markupsafe.escape": frozenset({HTML}),
    "flask.escape": frozenset({HTML}),
    "django.utils.html.escape": frozenset({HTML}),
}
_NUMERIC = frozenset({"int", "float", "uuid.UUID"})
_NORMALIZERS = frozenset({"os.path.realpath", "os.path.abspath", "os.path.normpath"})
_PROPAGATE_CALLS = frozenset(
    {"str", "bytes", "os.path.join", "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"}
)
_STR_METHODS = frozenset(
    {
        "capitalize",
        "casefold",
        "center",
        "decode",
        "encode",
        "expandtabs",
        "format",
        "format_map",
        "join",
        "ljust",
        "lower",
        "lstrip",
        "partition",
        "removeprefix",
        "removesuffix",
        "replace",
        "rjust",
        "rpartition",
        "rsplit",
        "rstrip",
        "split",
        "splitlines",
        "strip",
        "swapcase",
        "title",
        "translate",
        "upper",
        "zfill",
    }
)
_ARG_STR_METHODS = frozenset({"format", "format_map", "join", "replace"})  # the arguments end up in the result
_CONTAINER_METHODS = frozenset({"get", "getlist", "pop", "values", "items", "keys", "copy", "setdefault", "to_dict"})
_PATH_METHODS = frozenset({"joinpath", "with_name", "with_suffix", "with_stem", "absolute", "expanduser"})
_FASTAPI_ROUTES = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "api_route", "websocket"})
_STRINGY = frozenset({"str", "bytes", "Any", "typing.Any"})
_WRAPPERS = frozenset({"Optional", "List", "list", "Sequence", "Set", "set", "Union", "tuple", "Tuple"})
_DEPENDS = frozenset({"Depends", "Security"})
_TERMINATORS = frozenset({"abort", "flask.abort", "sys.exit", "exit", "quit"})
_FIXED_HOST = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}\s]+[/?#]")
_FIXED_PATH = re.compile(r"^/[^/\\]")
_TAINT_HINTS = re.compile(r"request|input|argv|environ|getenv|fastapi|anthropic|openai|litellm|ollama|langchain|genai")


@dataclass(frozen=True, slots=True)
class Origin:
    """One source of tainted data and the way it travelled."""

    kind: str  # 'request', 'llm', 'cli' or 'env'
    label: str  # human-readable source, for example 'flask request.args'
    cleared: frozenset[str]  # sink classes a sanitizer made this value safe for (plus the 'normalized' marker)
    trace: tuple[TraceStep, ...]

    def reaches(self, sink_class: str) -> bool:
        return sink_class not in self.cleared


Taint = tuple[Origin, ...]
State = dict[str, Taint]


class Resolver(Protocol):
    """What the analysis needs from the rule checker: import resolution and the names the file defines."""

    imported: set[str]
    aliases: dict[str, str]
    defined: set[str]

    def qualname(self, node: ast.AST) -> str | None: ...


def might_be_tainted(text: str) -> bool:
    """Cheap pre-check: a file that mentions no source at all needs no analysis."""
    return _TAINT_HINTS.search(text) is not None


def best(taint: Taint, sink_class: str, kinds: Iterable[str] | None = None) -> Origin | None:
    """The most relevant origin that reaches ``sink_class`` (LLM, then request, CLI, environment)."""
    allowed = frozenset(kinds) if kinds is not None else None
    candidates = [o for o in taint if o.reaches(sink_class) and (allowed is None or o.kind in allowed)]
    return min(candidates, key=lambda o: _KIND_ORDER[o.kind]) if candidates else None


def _union(*taints: Taint) -> Taint:
    seen: dict[tuple[str, str, frozenset[str]], Origin] = {}
    for taint in taints:
        for origin in taint:
            seen.setdefault((origin.kind, origin.label, origin.cleared), origin)
    return tuple(seen.values())[:MAX_ORIGINS]


def _clear(taint: Taint, classes: frozenset[str]) -> Taint:
    return tuple(Origin(o.kind, o.label, o.cleared | classes, o.trace) for o in taint)


def _step(taint: Taint, line: int, note: str) -> Taint:
    out = []
    for origin in taint:
        step = TraceStep(line, note)
        if len(origin.trace) >= MAX_TRACE or (origin.trace and origin.trace[-1] == step):
            out.append(origin)
        else:
            out.append(Origin(origin.kind, origin.label, origin.cleared, (*origin.trace, step)))
    return tuple(out)


def _join(*states: State) -> State:
    joined: State = {}
    for state in states:
        for key, taint in state.items():
            joined[key] = _union(joined.get(key, ()), taint)
    return joined


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


def _attr_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return list(reversed(parts))


def _terminates(body: list[ast.stmt], resolver: Resolver) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, ast.Raise | ast.Return | ast.Continue | ast.Break):
        return True
    return (
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and (resolver.qualname(last.value.func) in _TERMINATORS or _dotted(last.value.func) in _TERMINATORS)
    )


def analyze(tree: ast.Module, resolver: Resolver) -> dict[ast.AST, Taint]:
    """Taint of every call argument, keyword value and method receiver that carries any."""
    flow = _Flow(resolver)
    flow.block(tree.body, {})
    while flow.pending:  # function and class bodies met on the way, each with a fresh state
        scope = flow.pending.pop()
        flow.block(scope.body, flow.parameters(scope) if not isinstance(scope, ast.ClassDef) else {})
    return flow.found


class _Flow:
    def __init__(self, resolver: Resolver) -> None:
        self.r = resolver
        self.found: dict[ast.AST, Taint] = {}
        self.pending: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
        self._queued: set[int] = set()
        self.fastapi = "fastapi" in resolver.imported
        self.llm_libs = self._llm_libraries()

    def _llm_libraries(self) -> frozenset[str]:
        libs: set[str] = {name for name in ("anthropic", "openai", "litellm", "ollama") if name in self.r.imported}
        if any(top.startswith("langchain") for top in self.r.imported):
            libs.add("langchain")
        if any(value.startswith(("google.genai", "google.generativeai")) for value in self.r.aliases.values()):
            libs.add("genai")
        return frozenset(libs)

    # ----- FastAPI parameters

    def parameters(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> State:
        if not self.fastapi or not any(self._route(d) for d in node.decorator_list):
            return {}
        args = node.args
        positional = [*args.posonlyargs, *args.args]
        defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = [*zip(positional, defaults, strict=True), *zip(args.kwonlyargs, args.kw_defaults, strict=True)]
        state: State = {}
        for arg, default in pairs:
            if arg.arg in ("self", "cls") or self._depends(default) or not self._stringy(arg.annotation):
                continue
            label = f"FastAPI parameter `{arg.arg}`"
            state[arg.arg] = (Origin("request", label, frozenset(), (TraceStep(arg.lineno, f"{label} (source)"),)),)
        return state

    @staticmethod
    def _route(decorator: ast.expr) -> bool:
        return (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in _FASTAPI_ROUTES
            and isinstance(decorator.func.value, ast.Name | ast.Attribute)
        )

    def _depends(self, node: ast.expr | None) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = self.r.qualname(node.func) or _dotted(node.func) or ""
        return name.rsplit(".", 1)[-1] in _DEPENDS

    def _stringy(self, annotation: ast.expr | None, depth: int = 0) -> bool:
        if annotation is None:
            return True
        if depth > 6:
            return False
        if isinstance(annotation, ast.Constant):
            return annotation.value is None or annotation.value in ("str", "bytes")
        name = _dotted(annotation)
        if name is not None:
            return name in _STRINGY
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            return self._stringy(annotation.left, depth + 1) and self._stringy(annotation.right, depth + 1)
        if isinstance(annotation, ast.Subscript):
            base = (_dotted(annotation.value) or "").rsplit(".", 1)[-1]
            items = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
            if base == "Annotated":
                return self._stringy(items[0], depth + 1) and not any(self._depends(i) for i in items[1:])
            return base in _WRAPPERS and all(
                self._stringy(i, depth + 1) for i in items if not isinstance(i, ast.Constant) or i.value is not None
            )
        return False

    # ----- statements

    def block(self, body: list[ast.stmt], state: State) -> State:
        for stmt in body:
            state = self.stmt(stmt, state)
        return state

    def stmt(self, node: ast.stmt, state: State) -> State:
        if isinstance(node, ast.Assign):
            taint = self.expr(node.value, state)
            for target in node.targets:
                self.bind(target, taint, state, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.bind(node.target, self.expr(node.value, state), state, node.lineno)
        elif isinstance(node, ast.AugAssign):
            taint = self.expr(node.value, state)
            if isinstance(node.target, ast.Name):
                if taint:
                    combined = _union(state.get(node.target.id, ()), taint)
                    state[node.target.id] = _step(combined, node.lineno, f"appended to `{node.target.id}`")
            else:
                self.bind(node.target, taint, state, node.lineno, weak=True)
        elif isinstance(node, ast.If):
            return self._if(node, state)
        elif isinstance(node, ast.For | ast.AsyncFor):
            return self._for(node, state)
        elif isinstance(node, ast.While):
            return self._while(node, state)
        elif isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
            return self._try(node, state)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                taint = self.expr(item.context_expr, state)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, taint, state, node.lineno)
            return self.block(node.body, state)
        elif isinstance(node, ast.Match):
            self.expr(node.subject, state)
            branches = [self.block(case.body, dict(state)) for case in node.cases]
            return _join(state, *branches)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            state.pop(node.name, None)  # a scope of its own, analyzed separately
            if id(node) not in self._queued:
                self._queued.add(id(node))
                self.pending.append(node)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, state)
        return state

    def _if(self, node: ast.If, state: State) -> State:
        self.expr(node.test, state)
        body_in, else_in = dict(state), dict(state)
        for key, positive in self._guards(node.test):
            target = body_in if positive else else_in
            if key in target:
                target[key] = tuple(
                    Origin(o.kind, o.label, o.cleared | {PATH}, o.trace) if _NORMALIZED in o.cleared else o
                    for o in target[key]
                )
        body_out = self.block(node.body, body_in)
        else_out = self.block(node.orelse, else_in)
        live = [s for s, b in ((body_out, node.body), (else_out, node.orelse)) if not _terminates(b, self.r)]
        return _join(*live) if live else else_out

    def _guards(self, test: ast.expr) -> list[tuple[str, bool]]:
        """(name, True when the body is the guarded branch) for each startswith/is_relative_to containment check.

        In ``a and b`` every operand holds in the body; in ``a or b`` every operand is false in the else
        branch. Other combinations are not recognized.
        """
        if isinstance(test, ast.BoolOp):
            want = isinstance(test.op, ast.And)
            return [
                (key, positive) for value in test.values for key, positive in self._guards(value) if positive == want
            ]
        positive = True
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test, positive = test.operand, False
        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in ("startswith", "is_relative_to")
            and (key := _dotted(test.func.value)) is not None
        ):
            return [(key, positive)]
        return []

    def _for(self, node: ast.For | ast.AsyncFor, state: State) -> State:
        iterated = self.expr(node.iter, state)
        loop = state
        for _ in range(_LOOP_PASSES):
            entry = _join(state, loop)
            self.bind(node.target, iterated, entry, node.lineno)
            loop = self.block(node.body, entry)
        return self.block(node.orelse, _join(state, loop))

    def _while(self, node: ast.While, state: State) -> State:
        loop = state
        for _ in range(_LOOP_PASSES):
            entry = _join(state, loop)
            self.expr(node.test, entry)
            loop = self.block(node.body, entry)
        return self.block(node.orelse, _join(state, loop))

    def _try(self, node: ast.Try | ast.stmt, state: State) -> State:
        body: list[ast.stmt] = getattr(node, "body", [])
        handlers: list[ast.ExceptHandler] = getattr(node, "handlers", [])
        after_body = self.block(body, dict(state))
        normal = self.block(getattr(node, "orelse", []), after_body)
        outs = [normal]
        for handler in handlers:
            entry = _join(state, after_body)
            if handler.name:
                entry.pop(handler.name, None)
            outs.append(self.block(handler.body, entry))
        return self.block(getattr(node, "finalbody", []), _join(*outs))

    def bind(self, target: ast.AST, taint: Taint, state: State, line: int, *, weak: bool = False) -> None:
        if isinstance(target, ast.Name):
            if taint:
                state[target.id] = _step(taint, line, f"assigned to `{target.id}`")
            else:
                state.pop(target.id, None)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self.bind(element, taint, state, line, weak=weak)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, taint, state, line, weak=weak)
        elif isinstance(target, ast.Attribute) and not weak and (key := _dotted(target)) is not None:
            if taint:
                state[key] = _step(taint, line, f"assigned to `{key}`")
            else:
                state.pop(key, None)
        elif isinstance(target, ast.Subscript | ast.Attribute):
            container = target.value
            while isinstance(container, ast.Subscript | ast.Attribute) and _dotted(container) is None:
                container = container.value
            key = _dotted(container)
            if key is not None and taint:
                state[key] = _union(state.get(key, ()), _step(taint, line, f"stored in `{key}`"))

    # ----- expressions

    def expr(self, node: ast.expr | None, state: State, depth: int = 0) -> Taint:
        if node is None or depth > _MAX_DEPTH:
            return ()
        d = depth + 1
        if isinstance(node, ast.Name):
            return state.get(node.id, ())
        if isinstance(node, ast.Constant):
            return ()
        if isinstance(node, ast.Attribute):
            source = self._source_attribute(node)
            if source is not None:
                return source
            key = _dotted(node)
            if key is not None and key in state:
                return state[key]
            return self.expr(node.value, state, d)
        if isinstance(node, ast.Subscript):
            self.expr(node.slice, state, d)
            if self.r.qualname(node.value) == "os.environ":
                return self._origin("env", "environment variable (os.environ)", node)
            return self.expr(node.value, state, d)
        if isinstance(node, ast.Call):
            return self._call(node, state, d)
        if isinstance(node, ast.JoinedStr):
            taint = _union(*(self.expr(v, state, d) for v in node.values))
            first = node.values[0] if node.values else None
            prefix = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""
            return _clear(taint, _prefix_clears(prefix)) if taint else ()
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, state, d)
        if isinstance(node, ast.BinOp):
            taint = _union(self.expr(node.left, state, d), self.expr(node.right, state, d))
            left = node.left
            while isinstance(left, ast.BinOp):
                left = left.left
            if taint and isinstance(left, ast.Constant) and isinstance(left.value, str):
                return _clear(taint, _prefix_clears(left.value))
            return taint
        if isinstance(node, ast.BoolOp):
            return _union(*(self.expr(v, state, d) for v in node.values))
        if isinstance(node, ast.IfExp):
            self.expr(node.test, state, d)
            return _union(self.expr(node.body, state, d), self.expr(node.orelse, state, d))
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return _union(*(self.expr(e, state, d) for e in node.elts))
        if isinstance(node, ast.Dict):
            return _union(*(self.expr(e, state, d) for e in [*node.keys, *node.values] if e is not None))
        if isinstance(node, ast.Starred | ast.Await):
            return self.expr(node.value, state, d)
        if isinstance(node, ast.NamedExpr):
            taint = self.expr(node.value, state, d)
            self.bind(node.target, taint, state, node.lineno)
            return taint
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            return self._comprehension(node, state, d)
        if isinstance(node, ast.Lambda):
            return ()
        for child in ast.iter_child_nodes(node):  # Compare, UnaryOp, Slice, ...: evaluate for the calls inside
            if isinstance(child, ast.expr):
                self.expr(child, state, d)
        return ()

    def _comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp, state: State, depth: int
    ) -> Taint:
        inner = dict(state)
        for generator in node.generators:
            self.bind(generator.target, self.expr(generator.iter, inner, depth), inner, node.lineno)
            for condition in generator.ifs:
                self.expr(condition, inner, depth)
        if isinstance(node, ast.DictComp):
            return _union(self.expr(node.key, inner, depth), self.expr(node.value, inner, depth))
        return self.expr(node.elt, inner, depth)

    def _record(self, node: ast.AST, taint: Taint) -> None:
        if taint:
            self.found[node] = _union(self.found.get(node, ()), taint)

    def _call(self, node: ast.Call, state: State, depth: int) -> Taint:
        func = node.func
        receiver: Taint = ()
        if isinstance(func, ast.Attribute):
            receiver = self.expr(func.value, state, depth)
            self._record(func.value, receiver)
        args = [self.expr(a, state, depth) for a in node.args]
        for arg, taint in zip(node.args, args, strict=True):
            self._record(arg, taint)
        for keyword in node.keywords:
            taint = self.expr(keyword.value, state, depth)
            self._record(keyword.value, taint)
            args.append(taint)
        name = self.r.qualname(func)
        if name is None and isinstance(func, ast.Name) and func.id not in self.r.defined:
            name = func.id  # a builtin such as str, int or input, unless the file defines that name
        everything = _union(*args)
        if isinstance(func, ast.Attribute) and (source := self._source_attribute(func)) is not None:
            return source
        if name in _ENV_CALLS:
            return self._origin("env", f"environment variable ({name})", node)
        if name == "input":
            return self._origin("cli", "input()", node)
        llm = self._llm_call(node, name)
        if llm is not None:
            return self._origin("llm", f"LLM output of {llm}", node)
        if name in _NUMERIC:
            return ()
        if name in _CLEARING_CALLS:
            return _clear(args[0] if args else (), _CLEARING_CALLS[name])
        if name in _NORMALIZERS:
            return _clear(args[0] if args else (), frozenset({_NORMALIZED}))
        if name in _PROPAGATE_CALLS:
            return everything
        if isinstance(func, ast.Attribute):
            method = func.attr
            if method == "resolve" and receiver:
                return _clear(receiver, frozenset({_NORMALIZED}))
            if method in _STR_METHODS:
                extra = everything if method in _ARG_STR_METHODS else ()
                taint = _union(receiver, extra)
                is_literal = isinstance(func.value, ast.Constant) and isinstance(func.value.value, str)
                if taint and method in ("format", "format_map") and is_literal:
                    return _clear(taint, _prefix_clears(str(getattr(func.value, "value", ""))))
                return taint
            if method in _CONTAINER_METHODS or method in _PATH_METHODS:
                return receiver
        return ()

    def _llm_call(self, node: ast.Call, name: str | None) -> str | None:
        if not self.llm_libs:
            return None
        chain = _attr_chain(node.func)
        tail = ".".join(chain[-2:])
        if "anthropic" in self.llm_libs and tail == "messages.create":
            return tail
        if "openai" in self.llm_libs and tail in ("completions.create", "responses.create"):
            return ".".join(chain[-3:]) if chain[-3:-2] == ["chat"] else tail
        if name in ("litellm.completion", "litellm.acompletion", "ollama.chat", "ollama.generate"):
            return name
        if "genai" in self.llm_libs and chain[-1:] == ["generate_content"]:
            return "generate_content"
        if "langchain" in self.llm_libs and chain[-1:] in (["invoke"], ["ainvoke"]):
            return chain[-1]
        return None

    def _source_attribute(self, node: ast.Attribute) -> Taint | None:
        name = self.r.qualname(node)
        if name is not None:
            if name.startswith("flask.request.") and name.split(".")[2] in _FLASK_SOURCES and name.count(".") == 2:
                return self._origin("request", f"flask {name.removeprefix('flask.')}", node)
            if name == "sys.argv":
                return self._origin("cli", "sys.argv", node)
            return None
        holder = node.value
        if node.attr not in _DJANGO_SOURCES:
            return None
        if (isinstance(holder, ast.Name) and holder.id == "request" and "request" not in self.r.aliases) or (
            isinstance(holder, ast.Attribute) and holder.attr == "request"
        ):
            return self._origin("request", f"request.{node.attr}", node)
        return None

    @staticmethod
    def _origin(kind: str, label: str, node: ast.AST) -> Taint:
        line = getattr(node, "lineno", 1)
        return (Origin(kind, label, frozenset(), (TraceStep(line, f"{label} (source)"),)),)


def _prefix_clears(prefix: str) -> frozenset[str]:
    """Sink classes a fixed literal start makes safe: a fixed scheme and host, or a fixed local path."""
    if _FIXED_HOST.match(prefix):
        return frozenset({URL, REDIRECT})
    if _FIXED_PATH.match(prefix):
        return frozenset({REDIRECT})
    return frozenset()
