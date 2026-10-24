# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""PHP rules (``php.*``) over the tokenizer and the structural index. Source is never run.

Every rule matches one precise shape and says less when a value cannot be judged from the text. A request value
(``$_GET``, ``$_POST``, ``$_REQUEST``, ``$_COOKIE``, ``php://input``, a Laravel or Symfony request object ...) that
reaches a sink inside one function gives a finding with a trace; SQL sinks also report, at lower severity and
confidence, text built by concatenation or interpolation from a value that is not a literal (the strict reading of
``_built``). ``unserialize``, ``eval``/``assert``/``create_function`` and ``preg_replace`` ``/e`` have no rule: they had no
detection on the development data, only alerts (docs/benchmarks/cvefixes.md).
Blade templates (``*.blade.php``) are also checked for ``{!! !!}`` of a value that is not a literal.

Minified files (an average line longer than ``MAX_AVERAGE_LINE`` characters) are skipped as ``minified``; files over the
tokenizer's bounds, or past the work bound, as ``too_complex``.
"""

from __future__ import annotations

import re

from .models import Confidence, Severity, SkipReason, TraceStep, clip_snippet
from .php_index import (
    CLEAN,
    CLEARS,
    CODE,
    HTML,
    PATH,
    SHELL,
    SQL,
    URL,
    Index,
    Origin,
    TooComplex,
    best,
)
from .php_tokens import ISTR, NAME, NUM, PUNCT, STR, VAR, Token, tokenize
from .php_tokens import SHELL as SHELL_TOKEN
from .python_rules import _SQL
from .registry import Hit

PHP_SUFFIXES = frozenset({".php", ".phtml"})
MAX_AVERAGE_LINE = 500

# Only SQL reports an untainted "built" finding (concatenation or interpolation from a value that is not a literal),
# and only from the strict reading of "not a literal" in ``_built(tight=True)``: the wider readings, and the same finding
# for commands and ``eval``, were measured in docs/benchmarks/cvefixes.md and cost 30 to 100 alerts per extra detected pair.
_IDENTIFIER_NAME = re.compile(
    r"(?i)table|tbl|prefix|column|field|schema|database|(?:^|_)(?:db|col|cols|order|sort|dir|limit)(?:_|$)"
)

_SHELL_FUNCS = frozenset({"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"})
_SQL_FUNCS = frozenset(
    {"mysqli_query", "mysqli_multi_query", "mysqli_real_query", "mysqli_send_query", "pg_query", "pg_send_query"}
    | {
        "sqlsrv_query",
        "sqlite_query",
        "mssql_query",
        "odbc_exec",
        "mysql_query",
        "mysql_db_query",
        "mysql_unbuffered_query",
    }
    | {
        "db2_exec",
        "oci_parse",
        "pg_prepare",
        "mysqli_prepare",
        "sqlite_exec",
        "sqlite_array_query",
        "sqlite_single_query",
    }
)
_SQL_METHODS = frozenset({"query", "multi_query", "real_query", "unprepared", "statement"})
_SQL_KEYWORD_METHODS = frozenset({"exec", "prepare", "execute_query", "executequery"})
_WP_METHODS = frozenset({"get_results", "get_var", "get_row", "get_col", "query"})
_RAW_METHODS = frozenset(
    {
        "whereraw",
        "orwhereraw",
        "selectraw",
        "havingraw",
        "orhavingraw",
        "orderbyraw",
        "groupbyraw",
        "fromraw",
        "joinraw",
    }
    | {"wherenotraw", "orwherenotraw"}
)
_DB_STATIC = frozenset({"select", "statement", "unprepared", "insert", "update", "delete"})
_URL_FUNCS = frozenset(
    {"curl_init", "get_headers", "fsockopen", "pfsockopen", "stream_socket_client", "wp_remote_get", "wp_remote_post"}
    | {"wp_remote_head", "wp_remote_request"}
)
_DUAL_FILE_FUNCS = frozenset(
    {"file_get_contents", "fopen", "readfile", "file", "simplexml_load_file", "getimagesize", "copy"}
)
_PATH_ONLY: dict[str, tuple[int, ...]] = {
    "file_put_contents": (0,),
    "unlink": (0,),
    "rename": (0, 1),
    "mkdir": (0,),
    "rmdir": (0,),
    "scandir": (0,),
    "opendir": (0,),
    "move_uploaded_file": (1,),
    "highlight_file": (0,),
    "show_source": (0,),
    "parse_ini_file": (0,),
    "touch": (0,),
    "readlink": (0,),
}
_ECHO_FUNCS = frozenset({"printf", "vprintf"})
_PASSWORD = re.compile(r"(?:^|_)(?:pass|passwd|password|passphrase|pwd|userpass|userpwd)(?:_|$)")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_URL_START = re.compile(r"^\s*(?:https?:|ftp:|ftps:|//)", re.IGNORECASE)
_BLADE_COMMENT = re.compile(r"\{\{--.*?--\}\}", re.DOTALL)
_BLADE_VERBATIM = re.compile(r"@verbatim.*?@endverbatim", re.DOTALL)
_BLADE_RAW = re.compile(r"\{!!\s*(.*?)\s*!!\}", re.DOTALL)
_BLADE_SAFE = re.compile(
    r"""^(?:(?:csrf_field|csrf_token|method_field|route|url|asset|mix|vite|json_encode|e|__|trans|trans_choice|config
    |app|view|old_hidden|secure_asset|secure_url|action|collect|count|number_format|date|now|time)\s*\(
    |\$slot\b|\$(?:errors|attributes|__env|loop)\b|Form::|Html::|Js::|Vite::|Str::(?:of|slug|plural)\b
    |\$\w+->(?:links|render|toHtml|toJson|appends)\b|['"\d])""",
    re.VERBOSE,
)
_BLADE_SANITIZED = re.compile(
    r"\b(?:e|htmlspecialchars|htmlentities|strip_tags|clean|purify|sanitize\w*|Purifier::clean)\s*\("
)
_BLADE_REQUEST = re.compile(r"\$request\b|\brequest\s*\(|\bold\s*\(|\bInput::|\$_(?:GET|POST|REQUEST|COOKIE)\b")


def minified(text: str) -> bool:
    return len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE


def check_php(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one PHP file (or Blade template), or the reason it was not analyzed."""
    if minified(text):
        return "minified"
    tokens = tokenize(text)
    if tokens is None:
        return "too_complex"
    lines = text.splitlines()
    hits: list[Hit] = []
    if rel.lower().endswith(".blade.php"):
        hits.extend(_blade(text, lines))
    if tokens:
        try:
            hits.extend(_Checker(Index(tokens, lines), lines).run())
        except (TooComplex, RecursionError):
            return "too_complex"
    return _unique(hits)


def _unique(hits: list[Hit]) -> list[Hit]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Hit] = []
    for item in hits:
        key = (item.rule_id, item.line, item.column)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _blade(text: str, lines: list[str]) -> list[Hit]:
    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    cleaned = _BLADE_VERBATIM.sub(blank, _BLADE_COMMENT.sub(blank, text))
    hits: list[Hit] = []
    for match in _BLADE_RAW.finditer(cleaned):
        expr = match.group(1)
        if not expr or _BLADE_SAFE.match(expr) or _BLADE_SANITIZED.search(expr):
            continue
        line = cleaned.count("\n", 0, match.start()) + 1
        tainted = bool(_BLADE_REQUEST.search(expr))
        source = lines[line - 1] if 0 < line <= len(lines) else ""
        hits.append(
            Hit(
                "php.blade.unescaped",
                line,
                match.start() - cleaned.rfind("\n", 0, match.start()),
                line + expr.count("\n"),
                "Blade {!! !!} prints this value without escaping"
                + (" and it comes from the request." if tainted else " and it is not a literal."),
                clip_snippet(source),
                severity=None if tainted else "low",
                confidence="high" if tainted else "low",
            )
        )
    return hits


class _Checker:
    def __init__(self, index: Index, lines: list[str]) -> None:
        self.ix = index
        self.toks = index.toks
        self.lines = lines
        self.hits: list[Hit] = []

    # ----- output

    def hit(
        self,
        rule_id: str,
        at: int,
        message: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        cwe: str | None = None,
        origin: Origin | None = None,
        sink: str = "",
    ) -> None:
        tok = self.toks[at]
        text = self.lines[tok.line - 1] if 0 < tok.line <= len(self.lines) else ""
        trace: tuple[TraceStep, ...] = ()
        if origin is not None:
            trace = (*origin.trace, TraceStep(tok.line, f"reaches {sink}"))
            message = f"{message} The value comes from {origin.label} (line {origin.line})."
            confidence = confidence or ("high" if origin.label.startswith(("$_", "php://", "$HTTP")) else "medium")
        self.hits.append(
            Hit(
                rule_id,
                tok.line,
                tok.col,
                tok.end_line,
                message,
                clip_snippet(text),
                severity=severity,
                confidence=confidence,
                cwe=cwe,
                trace=trace,
            )
        )

    def flow(  # noqa: PLR0917 - one call per sink: the rule, where, what, the sink class and its name, the text
        self,
        rule_id: str,
        at: int,
        spans: list[tuple[int, int]],
        sink_class: str,
        sink: str,
        message: str,
        cwe: str | None = None,
    ) -> Origin | None:
        for lo, hi in spans:
            origin = best(self.ix.taint(lo, hi), sink_class)
            if origin is not None:
                self.hit(rule_id, at, message, origin=origin, sink=sink, cwe=cwe)
                return origin
        return None

    # ----- walk

    def run(self) -> list[Hit]:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind == SHELL_TOKEN:
                self._backtick(i, tok)
            elif tok.kind == NAME:
                self._name(i, tok)
        return self.hits

    def _name(self, i: int, tok: Token) -> None:
        toks = self.toks
        ix = self.ix
        word = tok.value.lstrip("\\").lower().rsplit("\\", 1)[-1]
        prev = toks[i - 1] if i else None
        if prev is not None and prev.kind == NAME and prev.value.lower() == "function":
            return
        if word in ("include", "include_once", "require", "require_once"):
            self._include(i, tok)
            return
        if word in ("echo", "print"):
            self._echo(i, tok)
            return
        if not ix.punct(i + 1, "(") or ix.match[i + 1] < 0:
            return
        args = ix.args(i + 1)
        if prev is not None and prev.kind == PUNCT and prev.value in ("->", "?->"):
            self._method(i, tok, word, args)
        elif prev is not None and prev.kind == PUNCT and prev.value == "::":
            cls = toks[i - 2].value.lstrip("\\").lower().rsplit("\\", 1)[-1] if i >= 2 else ""
            self._static(i, tok, cls, word, args)
        elif prev is not None and prev.kind == NAME and prev.value.lower() == "new":
            if word == "soapclient":
                self.flow(
                    "php.ssrf.request", i, args[:1], URL, "new SoapClient()", "A SOAP client is created from this URL."
                )
        else:
            self._function(i, tok, word, args)

    # ----- plain function calls

    def _function(self, i: int, tok: Token, word: str, args: list[tuple[int, int]]) -> None:
        if word in _SHELL_FUNCS:
            self._shell(i, word, args)
        elif word in _SQL_FUNCS:
            for span in args:
                if self._sql_arg(i, f"{word}()", span, keyword=False):
                    break
        elif word in _URL_FUNCS:
            self.flow(
                "php.ssrf.request", i, args[:1], URL, f"{word}()", f"{word}() requests a URL that the request controls."
            )
        elif word == "curl_setopt":
            self._curl_setopt(i, args)
        elif word == "curl_setopt_array":
            self._curl_setopt_array(i, args)
        elif word in _DUAL_FILE_FUNCS:
            self._dual_file(i, word, args)
        elif word in _PATH_ONLY:
            spans = [args[k] for k in _PATH_ONLY[word] if k < len(args)]
            self.flow(
                "php.path.traversal", i, spans, PATH, f"{word}()", f"{word}() uses a path built from request data."
            )
        elif word == "extract":
            self._extract(i, args)
        elif word in ("md5", "sha1", "hash"):
            self._weak_password_hash(i, word, args)
        elif word in ("exit", "die") and args:
            self.flow("php.xss.echo", i, args[:1], HTML, f"{word}()", f"{word}() prints this value into the response.")
        elif word in _ECHO_FUNCS:
            self.flow("php.xss.echo", i, args, HTML, f"{word}()", f"{word}() prints this value into the response.")

    def _method(self, i: int, tok: Token, word: str, args: list[tuple[int, int]]) -> None:
        toks = self.toks
        if word in _SQL_METHODS or (word in _WP_METHODS and i >= 2 and toks[i - 2].value == "wpdb"):
            if args:
                self._sql_arg(i, f"->{tok.value}()", args[0], keyword=False)
        elif word in _SQL_KEYWORD_METHODS and args:
            self._sql_arg(i, f"->{tok.value}()", args[0], keyword=True)
        elif word in _RAW_METHODS and args:
            self._sql_arg(i, f"->{tok.value}()", args[0], keyword=False, raw=True)

    def _static(self, i: int, tok: Token, cls: str, word: str, args: list[tuple[int, int]]) -> None:
        if cls.endswith("db") or cls == "capsule":
            if word == "raw" and args:
                self._sql_arg(i, "DB::raw()", args[0], keyword=False, raw=True)
            elif word in _DB_STATIC and args:
                self._sql_arg(i, f"DB::{tok.value}()", args[0], keyword=True)

    # ----- rules

    def _shell(self, i: int, word: str, args: list[tuple[int, int]]) -> None:
        if not args:
            return
        lo, hi = args[0]
        if (self.toks[lo].kind == PUNCT and self.toks[lo].value == "[") or self.ix.name_at(lo) == "array":
            return  # proc_open() with an argument array runs no shell
        message = f"{word}() runs a command built from request data."
        self.flow("php.exec.command", i, [(lo, hi)], SHELL, f"{word}()", message)

    def _backtick(self, i: int, tok: Token) -> None:
        origins = self.ix._interpolated(tok, i)
        origin = best(origins, SHELL)
        if origin is not None:
            self.hit(
                "php.exec.command", i, "A backtick command is built from request data.", origin=origin, sink="backticks"
            )

    def _include(self, i: int, tok: Token) -> None:
        lo = i + 1
        hi = self.ix.expr_end(lo)
        if lo < hi:
            self.flow(
                "php.include.dynamic",
                i,
                [(lo, hi)],
                PATH,
                tok.value,
                f"{tok.value} loads a file whose path is built from request data.",
            )

    def _echo(self, i: int, tok: Token) -> None:
        ix = self.ix
        k = i + 1
        while k < self.ix.n:
            end = ix.expr_end(k)
            if end > k:
                origin = best(ix.taint(k, end), HTML)
                if origin is not None:
                    self.hit(
                        "php.xss.echo",
                        i,
                        f"{tok.value} writes request data into the page without escaping it.",
                        origin=origin,
                        sink=tok.value,
                    )
                    return
            if tok.value.lower() == "echo" and ix.punct(end, ","):
                k = end + 1
            else:
                break

    def _curl_setopt(self, i: int, args: list[tuple[int, int]]) -> None:
        if len(args) >= 3 and self.toks[args[1][0]].value == "CURLOPT_URL" and args[1][1] == args[1][0] + 1:
            self.flow(
                "php.ssrf.request",
                i,
                [args[2]],
                URL,
                "curl_setopt(CURLOPT_URL)",
                "cURL requests a URL that the request controls.",
            )

    def _curl_setopt_array(self, i: int, args: list[tuple[int, int]]) -> None:
        if len(args) < 2:
            return
        lo = args[1][0]
        if not (self.ix.punct(lo, "[") or self.ix.name_at(lo) == "array"):
            return
        inner_open = lo if self.ix.punct(lo, "[") else lo + 1
        close = self.ix.match[inner_open]
        if close < 0:
            return
        for a, b in self.ix.split(inner_open + 1, close):
            for key, value in [self.ix.split(a, b, "=>")] if len(self.ix.split(a, b, "=>")) == 2 else []:
                if key[1] == key[0] + 1 and self.toks[key[0]].value == "CURLOPT_URL":
                    self.flow(
                        "php.ssrf.request",
                        i,
                        [value],
                        URL,
                        "curl_setopt_array(CURLOPT_URL)",
                        "cURL requests a URL that the request controls.",
                    )

    def _dual_file(self, i: int, word: str, args: list[tuple[int, int]]) -> None:
        if not args:
            return
        lo, hi = args[0]
        terms = self.ix.split(lo, hi, ".")
        first = terms[0] if terms else (lo, hi)
        first_tok = self.toks[first[0]]
        url_first = bool(self.ix.taint(*first)) or (first_tok.kind == STR and bool(_URL_START.match(first_tok.value)))
        if url_first:
            self.flow(
                "php.ssrf.request",
                i,
                [(lo, hi)],
                URL,
                f"{word}()",
                f"{word}() opens a location (a file or a URL) that the request controls.",
            )
        else:
            self.flow(
                "php.path.traversal",
                i,
                [(lo, hi)],
                PATH,
                f"{word}()",
                f"{word}() opens a path built from request data.",
            )

    def _extract(self, i: int, args: list[tuple[int, int]]) -> None:
        if not args:
            return
        if len(args) > 1 and any(t.value == "EXTR_PREFIX_ALL" for t in self.toks[args[1][0] : args[1][1]]):
            return
        lo, hi = args[0]
        origin = best(self.ix.taint(lo, hi), CODE) or best(self.ix.taint(lo, hi), CODE, objects=True)
        if origin is not None:
            self.hit(
                "php.extract.request",
                i,
                "extract() creates a variable for every key of request data, so a request can overwrite variables the code relies on.",
                origin=origin,
                sink="extract()",
            )

    def _weak_password_hash(self, i: int, word: str, args: list[tuple[int, int]]) -> None:
        if not args:
            return
        spans = args
        if word == "hash":
            first = self.toks[args[0][0]]
            if first.kind != STR or first.value.lower() not in ("md5", "sha1"):
                return
            spans = args[1:2]
        for lo, hi in spans:
            if _password_like(self.toks[lo:hi]):
                algo = word if word != "hash" else self.toks[args[0][0]].value.lower()
                self.hit(
                    "php.crypto.weak_password_hash",
                    i,
                    f"{algo} is a fast general-purpose hash, and it is applied to what looks like a password.",
                )
                return

    # ----- SQL

    def _sql_arg(self, i: int, sink: str, span: tuple[int, int], *, keyword: bool, raw: bool = False) -> bool:
        """Report SQL text built from request data, or from a value that is not a literal (the strict reading).

        ``keyword``: only text that reads as SQL counts (``->exec()``, ``->prepare()``, ``DB::select()`` take other things
        too). ``raw``: a fragment such as ``whereRaw("id = $id")``, which has no SQL keyword to look for."""
        lo, hi = span
        text = self._built(lo, hi)[1]
        sql_text = bool(_SQL.search(text))
        if keyword and not sql_text:
            return False
        origin = best(self.ix.taint(lo, hi), SQL)
        if origin is not None:
            self.hit("php.sql.injection", i, f"{sink} runs SQL built from request data.", origin=origin, sink=sink)
            return True
        if (raw or sql_text) and self._built(lo, hi, tight=True)[0]:
            self.hit(
                "php.sql.injection",
                i,
                f"{sink} runs SQL text built by concatenation or interpolation from a value that is not a literal.",
                severity="medium",
                confidence="low",
            )
            return True
        return False

    def _var_dynamic(self, name: str, pos: int, depth: int = 0, *, tight: bool = False) -> bool:
        if name in ("wpdb", "this") or (tight and _IDENTIFIER_NAME.search(name)):
            return False
        binds = self.ix.effective(name, pos)
        if not binds:
            return not tight  # a parameter or a global: unknown, so only the wide reading counts it
        return any(self._built(b.lo, b.hi, depth + 1, part=True, tight=tight)[0] for b in binds)

    def _built(self, lo: int, hi: int, depth: int = 0, *, part: bool = False, tight: bool = False) -> tuple[bool, str]:
        """(built from a part that is not a literal, the literal text it is built from).

        ``part``: the span is one operand of a larger string, so a call whose result is unknown counts as non-literal.
        ``tight``: the strict reading used for findings: a lone variable is not followed to what it was built from,
        parameters and globals do not count, and neither do names that read as a table, column or prefix."""
        ix = self.ix
        if lo >= hi or depth > 4:
            return False, ""
        terms = ix.split(lo, hi, ".")
        if len(terms) > 1:
            dynamic = False
            texts: list[str] = []
            for a, b in terms:
                d, t = self._built(a, b, depth + 1, part=True, tight=tight)
                dynamic = dynamic or d
                texts.append(t)
            return dynamic, " ? ".join(texts)
        toks = self.toks
        tok = toks[lo]
        if tok.kind in (STR, NUM):
            return False, tok.value
        if tok.kind == ISTR:
            return any(self._var_dynamic(name, lo, depth, tight=tight) for name in tok.vars), tok.value
        if tok.kind == PUNCT and tok.value == "(" and ix.match[lo] > lo:
            close = ix.match[lo]
            if lo + 2 == close and toks[lo + 1].kind == NAME and toks[lo + 1].value.lower() in _SAFE_CASTS:
                return False, ""
            if close + 1 == hi:
                return self._built(lo + 1, close, depth + 1, part=part, tight=tight)
            return part, ""
        if tok.kind == VAR:
            if ix.punct(lo + 1, "[", "->", "?->"):
                return part and self._var_dynamic(tok.value, lo, depth, tight=tight), ""
            binds = ix.effective(tok.value, lo) if part or not tight else []
            if not binds:
                return (part or not tight) and self._var_dynamic(tok.value, lo, depth, tight=tight), ""
            dynamic = False
            texts = []
            for bind in reversed(binds):
                d, t = self._built(bind.lo, bind.hi, depth + 1, part=part, tight=tight)
                dynamic = dynamic or d
                texts.append(t)
            return dynamic, " ".join(texts)
        if tok.kind == NAME:
            word = tok.value.lstrip("\\").lower().rsplit("\\", 1)[-1]
            if ix.punct(lo + 1, "(") and ix.match[lo + 1] > 0:
                if word in CLEAN or (word in CLEARS and SQL in CLEARS[word]):
                    return False, ""
                if word in ("sprintf", "vsprintf") and ix.match[lo + 1] + 1 == hi:
                    spans = ix.args(lo + 1)
                    if spans:
                        d, t = self._built(*spans[0], depth + 1, part=part, tight=tight)
                        rest = any(self._built(a, b, depth + 1, part=True, tight=tight)[0] for a, b in spans[1:])
                        return d or rest, t
                return part, ""
            return False, ""
        return part, ""


_SAFE_CASTS = frozenset({"int", "integer", "float", "double", "real", "bool", "boolean"})


def _password_like(window: list[Token]) -> bool:
    for tok in window:
        if tok.kind not in (VAR, STR, NAME):
            continue
        words = _CAMEL.sub("_", tok.value).lower() if tok.kind != STR or len(tok.value) < 40 else ""
        if words and _PASSWORD.search(words):
            return True
    return False
