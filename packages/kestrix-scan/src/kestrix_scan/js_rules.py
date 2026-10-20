# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""JavaScript and TypeScript rules (``js.*``) over the tokenizer and the structural index. Source is never run.

There is no full parser, so every rule matches a precise shape: a resolved call (``child_process.exec``
through any import or ``require`` alias), an assignment to a member (``.innerHTML =``), an object-literal key
(``rejectUnauthorized: false``) or a JSX attribute (``dangerouslySetInnerHTML``). A value counts as built
only when it is a template with a non-literal ``${}`` or a ``+`` concatenation with a non-literal part, and
literal names are followed through their bindings. When a shape is ambiguous the rule stays quiet.

Minified and bundled files (a ``.min.`` name, or an average line longer than ``MAX_AVERAGE_LINE``
characters) are skipped as ``minified``; files over the tokenizer's bounds as ``too_complex``.
"""

from __future__ import annotations

import bisect
import re

from .js_index import (
    CODE,
    CONFIDENCE,
    HTML,
    KEY,
    PATH,
    REDIRECT,
    SHELL,
    SQL,
    URL,
    Call,
    Chain,
    Index,
    Origin,
    best,
    is_punct,
)
from .js_tokens import JSX_ATTR, NAME, STR, TPL, TPL_HEAD, tokenize
from .models import Confidence, Severity, SkipReason, TraceStep, clip_snippet
from .python_rules import _SQL
from .registry import Hit

JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
_NO_JSX = frozenset({".ts", ".mts", ".cts"})
MAX_AVERAGE_LINE = 500

_REMOTE = frozenset({"request", "dom"})
_REQUEST = frozenset({"request"})
_LLM = frozenset({"llm"})
_LLM_CWE = {CODE: "CWE-94", SHELL: "CWE-78", HTML: "CWE-79"}
_LLM_WHAT = {CODE: "code", SHELL: "command", HTML: "HTML"}

_STRING_TIMERS = frozenset({"setTimeout", "setInterval", "setImmediate"})
_SHELL_ALWAYS = frozenset({"child_process.exec", "child_process.execSync"})
_SHELL_OPTION = {
    "child_process.spawn": 2,
    "child_process.spawnSync": 2,
    "child_process.execFile": 2,
    "child_process.execFileSync": 2,
}
_CHILD_PROCESS = frozenset({*_SHELL_ALWAYS, *_SHELL_OPTION, "child_process.fork"})
_SQL_METHODS = frozenset({"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe"})
_WEAK_HASHES = frozenset({"md5", "md4", "sha1", "sha-1"})
_FS_SINKS = frozenset(
    f"fs.{name}"
    for name in (
        "readFile",
        "readFileSync",
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "createReadStream",
        "createWriteStream",
        "unlink",
        "unlinkSync",
        "rm",
        "rmSync",
        "open",
        "openSync",
    )
)
_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "request")
_URL_SINKS = frozenset(
    {"fetch", "node-fetch", "undici.fetch", "undici.request", "axios", "got", "http.get", "http.request"}
    | {"https.get", "https.request"}
    | {f"{lib}.{verb}" for lib in ("axios", "got", "superagent") for verb in _HTTP_VERBS}
)
_CONFIG_URL_CALLS = frozenset({"axios", "axios.request"})
_REDIRECT_RECEIVERS = frozenset({"res", "response", "ctx", "reply"})
_MERGES = frozenset({"lodash.merge", "lodash.mergeWith", "lodash.defaultsDeep"})
_PROTO_KEYS = frozenset({"__proto__", "constructor", "prototype"})
_KEY_CHECKS = frozenset({"has", "includes", "hasOwnProperty"})
_HEADER_SETTERS = frozenset({"setHeader", "header", "set", "append"})
_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"
_HTML_SANITIZERS = frozenset({"sanitize", "sanitizeHtml", "escapeHtml", "escapeHTML", "escape", "encode"})

_WORDS = re.compile(r"[_\-]+|(?<=[a-z0-9])(?=[A-Z])")
_SECRET_WORDS = frozenset(
    {"token", "secret", "password", "passwd", "pwd", "passphrase", "nonce", "salt", "otp", "csrf", "apikey"}
)
_KEY_QUALIFIERS = frozenset({"api", "secret", "private", "access", "auth", "signing", "encryption", "session", "hmac"})
_NOT_SECRET = frozenset({"cache", "sort", "storage", "query", "map", "lookup", "index", "primary", "foreign", "react"})


def secret_name(name: str) -> bool:
    """True for names such as ``resetToken``, ``api_key`` or ``sessionSecret``; a bare ``key`` is a React key."""
    words = {word.lower() for word in _WORDS.split(name) if word}
    if words & _NOT_SECRET:
        return False
    return bool(words & _SECRET_WORDS) or ("key" in words and bool(words & _KEY_QUALIFIERS))


def minified(text: str, rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if ".min." in name or name.endswith("-min.js"):
        return True
    return len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE


def check_js(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one JavaScript or TypeScript file, or the reason it was not analyzed."""
    if minified(text, rel):
        return "minified"
    suffix = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    tokens = tokenize(text, jsx=suffix not in _NO_JSX, tsx=suffix == ".tsx")
    if tokens is None:
        return "too_complex"
    try:
        return _Checker(Index(tokens, text.splitlines())).run()
    except RecursionError:
        return "too_complex"


class _Checker:
    def __init__(self, index: Index) -> None:
        self.ix = index
        self.toks = index.toks
        self.hits: list[Hit] = []
        toks = self.toks
        relative = [k for k, t in enumerate(toks) if t.kind == NAME and t.value == "relative"]
        self.random_calls = [  # token indexes of Math.random
            k
            for k in range(index.n - 2)
            if toks[k].value == "Math" and is_punct(toks[k + 1], ".") and toks[k + 2].value == "random"
        ]
        self.relative_bindings = [  # (scope, binding, names in its value) for values that call path.relative
            (scope, binding, {t.value for t in toks[binding.lo : binding.hi]})
            for (scope, _), bindings in index.bindings.items()
            for binding in bindings
            if binding.kind == "value" and _any_between(relative, binding.lo, binding.hi)
        ]

    def hit(
        self,
        rule_id: str,
        at: int,
        message: str,
        severity: Severity | None = None,
        *,
        confidence: Confidence | None = None,
        cwe: str | None = None,
        trace: tuple[TraceStep, ...] = (),
    ) -> None:
        tok = self.toks[at]
        lines = self.ix.lines
        text = lines[tok.line - 1] if 0 < tok.line <= len(lines) else ""
        self.hits.append(
            Hit(
                rule_id=rule_id,
                line=tok.line,
                column=tok.col,
                end_line=tok.end_line,
                message=message,
                snippet=clip_snippet(text),
                severity=severity,
                confidence=confidence,
                cwe=cwe,
                trace=trace,
            )
        )

    def run(self) -> list[Hit]:
        for call in self.ix.calls:
            self._call(call)
        self._members()
        self._object_keys()
        self._insecure_random()
        self._cors_headers()
        unique: dict[tuple[str, int], Hit] = {}
        for item in self.hits:
            unique.setdefault((item.rule_id, item.line), item)
        return list(unique.values())

    # ----- shared helpers

    def _trace(self, origin: Origin, at: int, sink: str) -> tuple[TraceStep, ...]:
        return (*origin.trace, TraceStep(self.toks[at].line, f"reaches {sink}"))

    def _llm(self, at: int, origin: Origin, sink_class: str, sink: str) -> None:
        self.hit(
            "js.llm.output_to_sink",
            at,
            f"{origin.label} (line {origin.trace[0].line}) reaches {sink}. A prompt injection in anything the "
            f"model read can choose this {_LLM_WHAT[sink_class]}.",
            confidence="high",
            cwe=_LLM_CWE[sink_class],
            trace=self._trace(origin, at, sink),
        )

    def _sink(
        self,
        rule_id: str,
        at: int,
        span: tuple[int, int],
        *,
        sink_class: str,
        sink: str,
        message: str | None,
        severity: Severity | None = None,
    ) -> None:
        """A pattern hit (when ``message`` is set) that gains a trace from tainted data; LLM data reports js.llm."""
        origins = self.ix.taint(*span)
        llm = best(origins, sink_class, _LLM)
        if llm is not None:
            self._llm(at, llm, sink_class, sink)
            return
        origin = best(origins, sink_class, _REMOTE)
        if origin is not None:
            text = message or f"{sink} receives data from {origin.label}."
            self.hit(
                rule_id,
                at,
                f"{text} The value comes from {origin.label} (line {origin.trace[0].line}).",
                severity,
                confidence=CONFIDENCE[origin.kind],
                trace=self._trace(origin, at, sink),
            )
        elif message is not None:
            self.hit(rule_id, at, message, severity)

    def _stringy(self, lo: int, hi: int, depth: int = 0) -> str | None:
        """'literal' or 'built' when the span is a string value, None when it is not (or not known to be)."""
        ix = self.ix
        if lo >= hi or depth > 4:
            return None
        tok = self.toks[lo]
        if hi == lo + 1 and tok.kind in (STR, TPL):
            return "literal"
        if tok.kind == TPL_HEAD and ix.close_of(lo) + 1 == hi and not ix.tagged(lo):
            return "literal" if ix.literal(lo, hi) else "built"
        if len(ix.split(lo, hi, "+")) > 1:
            dynamic, text = ix.built_string(lo, hi)
            if dynamic:
                return "built"
            return "literal" if text or ix.literal(lo, hi) else None
        if hi == lo + 1 and tok.kind == NAME:
            kinds = {self._stringy(b.lo, b.hi, depth + 1) for b in ix.lookup(tok.value, lo) or () if b.kind == "value"}
            return "built" if "built" in kinds else "literal" if "literal" in kinds else None
        return None

    def _sanitized_html(self, lo: int, hi: int) -> bool:
        if self.toks[lo].kind != NAME:
            return False
        chain = self.ix.chain_after(lo)
        segs = chain.segs
        return (
            chain.end == hi
            and len(segs) >= 2
            and segs[-1].kind == "call"
            and segs[-2].kind == "name"
            and segs[-2].value in _HTML_SANITIZERS
        )

    def _xss(self, at: int, span: tuple[int, int], sink: str, *, jquery: bool = False) -> None:
        lo, hi = span
        if lo >= hi or self.ix.literal(lo, hi) or self._sanitized_html(lo, hi):
            return
        origins = self.ix.taint(lo, hi)
        llm = best(origins, HTML, _LLM)
        if llm is not None:
            self._llm(at, llm, HTML, sink)
            return
        if origins and all(HTML in o.cleared for o in origins):
            return
        origin = best(origins, HTML, _REMOTE)
        what = "jQuery .html()" if jquery else sink
        if origin is None:
            self.hit("js.dom.xss_sink", at, f"{what} receives a value that is not a literal.", "medium")
            return
        self.hit(
            "js.dom.xss_sink",
            at,
            f"{what} receives {origin.label} (line {origin.trace[0].line}), which an attacker can set through a link.",
            confidence=CONFIDENCE[origin.kind],
            trace=self._trace(origin, at, sink),
        )

    def _taint_hit(
        self, rule_id: str, at: int, span: tuple[int, int], *, sink_class: str, sink: str, verb: str
    ) -> None:
        origin = best(self.ix.taint(*span), sink_class, _REQUEST)
        if origin is not None:
            self.hit(
                rule_id,
                at,
                f"{sink} {verb} {origin.label} (line {origin.trace[0].line}).",
                confidence=CONFIDENCE[origin.kind],
                trace=self._trace(origin, at, sink),
            )

    # ----- calls

    def _call(self, call: Call) -> None:
        ix = self.ix
        name = ix.qualname(call.callee)
        segs = call.callee.segs
        last = segs[-1].value if segs[-1].kind == "name" else ""
        args = call.args
        at = segs[-1].index if segs[-1].kind == "name" else call.open
        first = args[0] if args else None
        if name == "eval" and first is not None and not ix.literal(*first):
            message = "eval() runs a value that is not a literal as code."
            self._sink("js.exec.eval", at, first, sink_class=CODE, sink="eval()", message=message)
        elif name == "Function" and args and not all(ix.literal(*arg) for arg in args):
            message = "new Function() builds code from a value that is not a literal."
            self._sink("js.exec.eval", at, args[-1], sink_class=CODE, sink="Function()", message=message)
        elif name in _STRING_TIMERS and first is not None:
            self._timer(at, name, first)
        elif name in _CHILD_PROCESS and first is not None:
            self._child_process(at, name, call)
        elif name in ("document.write", "document.writeln") and first is not None:
            self._xss(at, first, f"{name}()")
        elif last == "insertAdjacentHTML" and len(args) >= 2 and len(segs) >= 2:
            self._xss(at, args[1], "insertAdjacentHTML()")
        elif last == "html" and first is not None and len(segs) >= 2 and self._jquery(call):
            self._xss(at, first, ".html()", jquery=True)
        elif last in _SQL_METHODS and first is not None and len(segs) >= 2:
            dynamic, text = ix.built_string(*first)
            if dynamic and _SQL.search(text):
                message = f"SQL text passed to .{last}() is built with a template literal or concatenation."
                self._sink("js.sql.string_built", at, first, sink_class=SQL, sink=f".{last}()", message=message)
        elif name == "crypto.createHash" and first is not None:
            algorithm = ix.string_value(*first)
            if algorithm is not None and algorithm.lower() in _WEAK_HASHES:
                self.hit("js.crypto.weak_hash", at, f"crypto.createHash('{algorithm}') uses a broken hash.")
        elif name == "jsonwebtoken.verify" and len(args) >= 3:
            self._jwt(at, args[2])
        elif name == "cors" and first is not None:
            self._cors_call(at, first)
        self._data_flow(call, name, last, at)

    def _timer(self, at: int, name: str, arg: tuple[int, int]) -> None:
        kind = self._stringy(*arg)
        if kind == "literal":
            self.hit("js.exec.eval", at, f"{name}() with a string argument evaluates it as code.", "low")
        elif kind == "built":
            message = f"{name}() with a built string evaluates it as code."
            self._sink("js.exec.eval", at, arg, sink_class=CODE, sink=f"{name}()", message=message)

    def _child_process(self, at: int, name: str, call: Call) -> None:
        ix = self.ix
        args = call.args
        command = args[0]
        short = name.split(".", 1)[1]
        if name in _SHELL_ALWAYS:
            built = self._stringy(*command) == "built"
            message = f"{short}() runs a command built from a template or concatenation through the shell."
            self._sink(
                "js.child_process.shell",
                at,
                command,
                sink_class=SHELL,
                sink=f"{short}()",
                message=message if built else None,
            )
            return
        options = next(
            (entries for arg in args[1:] if (entries := ix.object_entries(*arg)) is not None and "shell" in entries),
            None,
        )
        shell = options is not None and ix.toks[options["shell"][0]].value == "true"
        if shell:
            fixed = ix.literal(*command) and (len(args) < 2 or ix.literal(*args[1]) or ix.object_entries(*args[1]))
            message = f"{short}() with shell: true runs a command that is not a literal through the shell."
            self._sink(
                "js.child_process.shell",
                at,
                command,
                sink_class=SHELL,
                sink=f"{short}()",
                message=None if fixed else message,
            )
        else:
            origins = ix.taint(*command)
            llm = best(origins, SHELL, _LLM)
            if llm is not None:
                self._llm(at, llm, SHELL, f"{short}()")

    def _jquery(self, call: Call) -> bool:
        segs = call.callee.segs
        if segs[0].kind == "name" and segs[0].value in ("$", "jQuery") and len(segs) >= 2 and segs[1].kind == "call":
            return True
        return any(seg.kind == "name" and seg.value.startswith("$") and len(seg.value) > 1 for seg in segs[:-1])

    def _jwt(self, at: int, options_span: tuple[int, int]) -> None:
        ix = self.ix
        options = ix.object_entries(*options_span)
        if options is None:
            return
        if "algorithms" in options:
            lo, hi = options["algorithms"]
            if any(tok.kind == STR and tok.value.lower() == "none" for tok in ix.toks[lo:hi]):
                self.hit("js.jwt.no_verify", at, "jwt.verify accepts the 'none' algorithm, so unsigned tokens pass.")
        if "ignoreExpiration" in options:
            lo, _ = options["ignoreExpiration"]
            if ix.toks[lo].value == "true":
                self.hit(
                    "js.jwt.no_verify", at, "jwt.verify with ignoreExpiration: true accepts expired tokens.", "low"
                )

    def _cors_call(self, at: int, span: tuple[int, int]) -> None:
        ix = self.ix
        options = ix.object_entries(*span)
        if options is None or "origin" not in options or "credentials" not in options:
            return
        origin = ix.toks[options["origin"][0]]
        any_origin = (origin.kind == NAME and origin.value == "true") or (origin.kind == STR and origin.value == "*")
        if any_origin and ix.toks[options["credentials"][0]].value == "true":
            self.hit(
                "js.cors.wildcard_credentials",
                at,
                "cors() allows every origin with credentials: any site can make credentialed requests and read the replies.",
            )

    def _data_flow(self, call: Call, name: str | None, last: str, at: int) -> None:
        """The taint-only rules: path traversal, SSRF, open redirects and lodash merges of request data."""
        ix = self.ix
        args = call.args
        segs = call.callee.segs
        if not args:
            return
        first = args[0]
        receiver = segs[0].value if len(segs) == 2 and segs[0].kind == "name" else ""
        if name in _FS_SINKS:
            self._path(at, first, f"{name}()")
        elif last == "sendFile" and len(segs) >= 2:
            entries = ix.object_entries(*args[1]) if len(args) >= 2 else None
            if entries is None or "root" not in entries:
                self._path(at, first, "res.sendFile()")
        elif last == "download" and receiver in ("res", "response"):
            self._path(at, first, "res.download()")
        if name in _URL_SINKS:
            span = first
            if name in _CONFIG_URL_CALLS and (entries := ix.object_entries(*first)) is not None:
                if "url" not in entries:
                    return
                span = entries["url"]
            self._taint_hit(
                "js.ssrf.request", at, span, sink_class=URL, sink=f"{name}()", verb="fetches a URL taken from"
            )
        elif last == "redirect" and receiver in _REDIRECT_RECEIVERS:
            sink = f"{receiver}.redirect()"
            self._taint_hit("js.redirect.open", at, args[-1], sink_class=REDIRECT, sink=sink, verb="redirects to")
        elif name in _MERGES:
            for arg in args[1:]:
                origin = best(ix.taint(*arg), KEY, _REQUEST)
                if origin is not None:
                    self.hit(
                        "js.proto.pollution",
                        at,
                        f"{name}() deep-merges {origin.label} (line {origin.trace[0].line}); a __proto__ key in it "
                        "changes Object.prototype on older lodash versions.",
                        trace=self._trace(origin, at, f"{name}()"),
                    )
                    break

    def _path(self, at: int, span: tuple[int, int], sink: str) -> None:
        origin = best(self.ix.taint(*span), PATH, _REQUEST)
        if origin is None or self._guarded_path(span, at):
            return
        self.hit(
            "js.path.traversal",
            at,
            f"{sink} receives a path taken from {origin.label} (line {origin.trace[0].line}).",
            confidence=CONFIDENCE[origin.kind],
            trace=self._trace(origin, at, sink),
        )

    def _guarded_path(self, span: tuple[int, int], at: int) -> bool:
        """A name in the path argument was resolved (or made relative) and then checked with startsWith."""
        ix = self.ix
        toks = self.toks
        for k in range(*span):
            tok = toks[k]
            if tok.kind != NAME or (k > 0 and is_punct(toks[k - 1], ".", "?.")):
                continue
            for binding in ix.lookup(tok.value, k) or ():
                values = {t.value for t in toks[binding.lo : binding.hi]}
                resolved = binding.kind == "value" and values & {"resolve", "normalize", "realpath", "realpathSync"}
                if resolved and self._starts_with_check(tok.value, binding.pos, at):
                    return True
        return any(self._starts_with_check(name, pos, at) for name, pos in self._relative_checks(span, at))

    def _relative_checks(self, span: tuple[int, int], at: int) -> list[tuple[str, int]]:
        """Names bound to ``path.relative(base, x)`` for a name ``x`` used in the path argument."""
        toks = self.toks
        used = {toks[k].value for k in range(*span) if toks[k].kind == NAME}
        visible = set(self.ix.scope_chain(at))
        return [
            (binding.name, binding.pos)
            for scope, binding, values in self.relative_bindings
            if scope in visible and binding.pos < at and used & values
        ]

    def _starts_with_check(self, name: str, after: int, before: int) -> bool:
        toks = self.toks
        for k in range(after, before - 2):
            if (
                toks[k].kind == NAME
                and toks[k].value == name
                and is_punct(toks[k + 1], ".", "?.")
                and toks[k + 2].kind == NAME
                and toks[k + 2].value == "startsWith"
            ):
                return True
        return False

    # ----- members, keys and JSX attributes

    def _members(self) -> None:
        """``x.innerHTML = v``, ``x.rejectUnauthorized = false``, the TLS environment variable, ``obj[key] = v``."""
        ix = self.ix
        toks = self.toks
        for k, tok in enumerate(toks):
            if not is_punct(tok, "=", "+=") or k == 0:
                continue
            target = toks[k - 1]
            value = (k + 1, ix.expr_end(k + 1, comma=False))
            dotted = k >= 2 and is_punct(toks[k - 2], ".", "?.")
            if target.kind == NAME and dotted and target.value in ("innerHTML", "outerHTML"):
                self._xss(k - 1, value, f".{target.value} =")
            elif target.kind == NAME and dotted and target.value == "rejectUnauthorized" and _false(ix, value):
                self.hit(
                    "js.tls.reject_unauthorized",
                    k - 1,
                    "TLS certificate checks switched off (rejectUnauthorized = false).",
                )
            elif tok.value == "=" and _tls_env_target(ix, k - 1) and _zero(ix, value):
                self.hit(
                    "js.tls.reject_unauthorized",
                    k - 1,
                    "NODE_TLS_REJECT_UNAUTHORIZED=0 switches off certificate checks for every TLS connection in the process.",
                )
            elif tok.value == "=" and is_punct(target, "]"):
                self._bracket_assignment(k, value)

    def _bracket_assignment(self, eq: int, value: tuple[int, int]) -> None:
        ix = self.ix
        if ix.strings & _PROTO_KEYS:
            return  # the file names __proto__/constructor/prototype, most likely in a guard
        chain = ix.chain_before(eq - 1)
        if chain is None:
            return
        keys = [seg for seg in chain.segs if seg.kind == "index"]
        for position, seg in enumerate(keys):
            close = ix.close_of(seg.index)
            origin = best(ix.taint(seg.index + 1, close), KEY, _REQUEST)
            if origin is None:
                continue
            nested = position < len(keys) - 1
            if not nested and best(ix.taint(*value), KEY, _REQUEST) is None:
                continue
            if self._null_prototype(chain) or self._allowlisted(seg.index + 1, close, eq):
                return
            self.hit(
                "js.proto.pollution",
                seg.index,
                f"An object key taken from {origin.label} (line {origin.trace[0].line}) is assigned without a "
                "__proto__/constructor check.",
                trace=self._trace(origin, seg.index, "obj[key] ="),
            )
            return

    def _allowlisted(self, lo: int, hi: int, eq: int) -> bool:
        """The key is a single name checked earlier in its function with ``.has(key)``, ``.includes(key)`` or
        ``.hasOwnProperty(key)``, as in ``if (ALLOWED.has(key)) obj[key] = v``."""
        toks = self.toks
        if hi != lo + 1 or toks[lo].kind != NAME:
            return False
        name = toks[lo].value
        start = max(self.ix.scopes[self.ix.scope_of[eq]].open, 0)
        return any(
            toks[k].value in _KEY_CHECKS
            and is_punct(toks[k + 1], "(")
            and toks[k + 2].value == name
            and is_punct(toks[k + 3], ")")
            for k in range(start, eq - 3)
        )

    def _null_prototype(self, chain: Chain) -> bool:
        first = chain.segs[0]
        if first.kind != "name":
            return False
        for binding in self.ix.lookup(first.value, first.index) or ():
            values = [t.value for t in self.toks[binding.lo : binding.hi]]
            if "Map" in values or ("create" in values and "null" in values):
                return True
        return False

    def _object_keys(self) -> None:
        """``rejectUnauthorized: false``, ``NODE_TLS_REJECT_UNAUTHORIZED: '0'`` and ``dangerouslySetInnerHTML``."""
        ix = self.ix
        toks = self.toks
        for k, tok in enumerate(toks):
            if tok.value == "dangerouslySetInnerHTML" and tok.kind in (NAME, JSX_ATTR, STR):
                self._dangerous_html(k)
                continue
            if tok.kind not in (NAME, STR) or k + 1 >= ix.n or not is_punct(toks[k + 1], ":"):
                continue
            if k == 0 or not is_punct(toks[k - 1], "{", ","):
                continue
            value = (k + 2, ix.expr_end(k + 2))
            if tok.value == "rejectUnauthorized" and _false(ix, value):
                self.hit(
                    "js.tls.reject_unauthorized", k, "TLS certificate checks switched off (rejectUnauthorized: false)."
                )
            elif tok.value == "NODE_TLS_REJECT_UNAUTHORIZED" and _zero(ix, value):
                self.hit(
                    "js.tls.reject_unauthorized",
                    k,
                    "NODE_TLS_REJECT_UNAUTHORIZED: '0' in an environment switches off certificate checks for that process.",
                )

    def _dangerous_html(self, k: int) -> None:
        ix = self.ix
        toks = self.toks
        if k + 2 >= ix.n:
            return
        if is_punct(toks[k + 1], "=") and is_punct(toks[k + 2], "{"):
            span = (k + 3, ix.close_of(k + 2))
        elif is_punct(toks[k + 1], ":"):
            span = (k + 2, ix.expr_end(k + 2))
        else:
            return
        entries = ix.object_entries(*span)
        if entries is not None:
            if "__html" in entries:
                self._xss(k, entries["__html"], "dangerouslySetInnerHTML")
            return
        origins = ix.taint(*span)
        if best(origins, HTML, _LLM | _REMOTE) is not None:
            self._xss(k, span, "dangerouslySetInnerHTML")

    # ----- insecure randomness

    def _insecure_random(self) -> None:
        ix = self.ix
        toks = self.toks
        if not self.random_calls:
            return
        for (_, name), bindings in ix.bindings.items():
            if not secret_name(name):
                continue
            for binding in bindings:
                if binding.kind == "value" and self._math_random(binding.lo, binding.hi):
                    self.hit("js.crypto.insecure_random", binding.pos, f"'{name}' is generated with Math.random().")
        for k, tok in enumerate(toks):
            if tok.kind not in (NAME, STR) or k + 1 >= ix.n or not secret_name(tok.value):
                continue
            nxt = toks[k + 1]
            member = k > 0 and is_punct(toks[k - 1], ".", "?.") and is_punct(nxt, "=")
            key = k > 0 and is_punct(toks[k - 1], "{", ",") and is_punct(nxt, ":")
            if member or key:
                value = (k + 2, ix.expr_end(k + 2, comma=key))
                if self._math_random(*value):
                    self.hit("js.crypto.insecure_random", k, f"'{tok.value}' is generated with Math.random().")
        for scope in ix.scopes[1:]:
            if not scope.name or not secret_name(scope.name):
                continue
            for k in range(scope.open + 1, min(scope.close, ix.n)):
                returned = toks[k].kind == NAME and toks[k].value == "return" and ix.scope_of[k] == scope.id
                if returned and self._math_random(k + 1, ix.expr_end(k + 1, comma=False)):
                    self.hit("js.crypto.insecure_random", k, f"{scope.name}() returns a value made with Math.random().")

    def _math_random(self, lo: int, hi: int) -> bool:
        return "Math" not in self.ix.declared and _any_between(self.random_calls, lo, hi)

    # ----- CORS headers

    def _cors_headers(self) -> None:
        """Access-Control-Allow-Origin: * (or the request's Origin) with Allow-Credentials: true in one function."""
        ix = self.ix
        toks = self.toks
        origins: dict[int, int] = {}
        credentials: set[int] = set()
        for name, value, at in self._headers():
            scope = ix.scope_of[at]
            if name == _ACAO and self._any_origin(value):
                origins.setdefault(scope, at)
            elif name == _ACAC and value[1] > value[0] and toks[value[0]].value == "true":
                credentials.add(scope)
        for scope, at in origins.items():
            if scope in credentials:
                self.hit(
                    "js.cors.wildcard_credentials",
                    at,
                    "Access-Control-Allow-Origin is * or the request's own Origin, together with "
                    "Access-Control-Allow-Credentials: true.",
                )

    def _headers(self) -> list[tuple[str, tuple[int, int], int]]:
        ix = self.ix
        toks = self.toks
        found = []
        for call in ix.calls:
            segs = call.callee.segs
            if segs[-1].kind == "name" and segs[-1].value in _HEADER_SETTERS and len(call.args) >= 2:
                name = ix.string_value(*call.args[0])
                if name is not None:
                    found.append((name.lower(), call.args[1], segs[-1].index))
        for k, tok in enumerate(toks):
            if tok.kind == STR and tok.value.lower() in (_ACAO, _ACAC) and k + 1 < ix.n and is_punct(toks[k + 1], ":"):
                found.append((tok.value.lower(), (k + 2, ix.expr_end(k + 2)), k))
        return found

    def _any_origin(self, value: tuple[int, int]) -> bool:
        toks = self.toks
        lo, hi = value
        if self.ix.string_value(lo, hi) == "*":
            return True
        return any(
            (toks[k].kind == STR and toks[k].value.lower() == "origin")
            or (toks[k].value == "origin" and k > 0 and is_punct(toks[k - 1], ".", "?."))
            for k in range(lo, hi)
        )


def _any_between(positions: list[int], lo: int, hi: int) -> bool:
    """True when the sorted ``positions`` hold an index in ``lo:hi``."""
    at = bisect.bisect_left(positions, lo)
    return at < len(positions) and positions[at] < hi


def _false(ix: Index, span: tuple[int, int]) -> bool:
    lo, hi = span
    return hi == lo + 1 and ix.toks[lo].kind == NAME and ix.toks[lo].value == "false"


def _zero(ix: Index, span: tuple[int, int]) -> bool:
    lo, hi = span
    return hi == lo + 1 and ix.toks[lo].value == "0" and ix.toks[lo].kind in (STR, TPL, "num")


def _tls_env_target(ix: Index, end: int) -> bool:
    """``process.env.NODE_TLS_REJECT_UNAUTHORIZED`` or ``process.env['NODE_TLS_REJECT_UNAUTHORIZED']`` ends at ``end``."""
    tok = ix.toks[end]
    if tok.kind == NAME:
        return tok.value == "NODE_TLS_REJECT_UNAUTHORIZED"
    if is_punct(tok, "]"):
        opener = ix.match[end]
        return opener >= 0 and ix.string_value(opener + 1, end) == "NODE_TLS_REJECT_UNAUTHORIZED"
    return False
