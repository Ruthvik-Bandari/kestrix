# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A structural index over PHP tokens: the matcher the ``php.*`` rules are written against.

There is no syntax tree. The index knows the matching bracket of every ``(``, ``[`` and ``{``; the functions of a
file (``function name(...) {`` and closures, with their parameters; arrow functions share their parent's scope);
the assignments to each variable (``=``, ``.=``, ``??=``, ``foreach`` variables, ``list()`` and ``[...] =``
destructuring); and whether a parameter is a request object (named ``$request`` or ``$req``, or typed with a
name that contains ``Request``).

**Taint** stays inside a function and the closures in it; it never crosses into a called function. Sources:

- ``$_GET``, ``$_POST``, ``$_REQUEST``, ``$_COOKIE`` (and the legacy ``$HTTP_GET_VARS`` family), ``$_SERVER`` with a
  request field (``QUERY_STRING``, ``REQUEST_URI``, ``PATH_INFO``, ``PHP_SELF``, ``HTTP_*`` ...), the ``name`` of a
  ``$_FILES`` entry, ``php://input``, ``getallheaders()``, ``filter_input()``, Laravel's ``request()`` and
  ``Request::input()``, a request-object parameter's ``input()``, ``get()``, ``query()``, ``post()``, ``all()``,
  ``cookie()``, ``header()``, ``getContent()``, ``getQueryParams()``, ``getParsedBody()`` and so on, its
  ``->query->get()`` and ``->request->get()`` bags and its dynamic properties, CodeIgniter's
  ``$this->input->get()`` and CakePHP's ``$this->request->getQuery()``.

It flows through assignments, ``.`` concatenation, interpolated strings and heredocs, ``?:``/``??``/ternaries,
array literals, subscripts and properties, and the string and array functions in ``_PROPAGATE``. Every other call
returns clean data. Comparisons, arithmetic, ``!`` and numeric casts or functions give clean values. Sanitizers
clear one class of sink (``escapeshellarg`` for commands, ``htmlspecialchars`` for HTML, ``basename`` for paths,
``mysqli_real_escape_string`` and ``$pdo->quote`` for SQL ...); numeric casts and hashes clear all of them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import pairwise

from .models import TraceStep
from .php_tokens import ISTR, NAME, NUM, PUNCT, STR, VAR, Token

MAX_DEPTH = 40
MAX_STEPS = 3_000_000  # work bound; past it the file is reported as too complex
MAX_EXPR = 8192  # tokens an assignment's right-hand side is followed for
MAX_BINDINGS = 64  # assignments to one variable that a lookup considers
MAX_ORIGINS = 4
MAX_TRACE = 8

SHELL, PATH, SQL, HTML, URL, CODE, DESER = "shell", "path", "sql", "html", "url", "code", "deser"
ALL = frozenset({SHELL, PATH, SQL, HTML, URL, CODE, DESER})


class TooComplex(Exception):
    """The work bound was exceeded."""


@dataclass(frozen=True, slots=True)
class Origin:
    label: str  # what the data comes from, for example '$_GET'
    line: int
    cleared: frozenset[str] = frozenset()  # sink classes a sanitizer on the way made safe
    obj: bool = False  # a request object or parameter bag; its values are tainted, it is not itself
    trace: tuple[TraceStep, ...] = ()


@dataclass(slots=True)
class Scope:
    id: int
    lo: int  # token index of the opening brace
    hi: int  # token index of the closing brace
    parent: int
    closure: bool
    requests: set[str] = field(default_factory=set)  # parameters that are request objects


@dataclass(frozen=True, slots=True)
class Bind:
    pos: int  # token index of the assigned variable
    depth: int  # brace depth there
    lo: int  # the value's token span
    hi: int
    definite: bool  # a plain ``=`` (it replaces earlier values) rather than ``.=``, ``??=`` or an element assignment


_SUPERGLOBALS = frozenset(
    {
        "_GET",
        "_POST",
        "_REQUEST",
        "_COOKIE",
        "HTTP_GET_VARS",
        "HTTP_POST_VARS",
        "HTTP_COOKIE_VARS",
        "HTTP_RAW_POST_DATA",
    }
)
_SERVER_FIELD = re.compile(
    r"^(?:QUERY_STRING|REQUEST_URI|PATH_INFO|ORIG_PATH_INFO|PATH_TRANSLATED|PHP_SELF|REQUEST_METHOD_OVERRIDE"
    r"|HTTP_[A-Z0-9_]+|REDIRECT_QUERY_STRING|REDIRECT_URL|CONTENT_TYPE|PHP_AUTH_USER|PHP_AUTH_PW)$",
    re.IGNORECASE,
)
_ASSIGN_OPS = frozenset({"=", ".=", "??="})
_OPEN = frozenset("([{")
_CLOSE = frozenset(")]}")
_MATCH_OF = {")": "(", "]": "[", "}": "{"}
_CLEAN_CASTS = frozenset({"int", "integer", "float", "double", "real", "bool", "boolean", "unset"})
_ALL_CASTS = _CLEAN_CASTS | {"string", "array", "object", "binary"}
_LOW_NAMES = frozenset({"and", "or", "xor", "instanceof"})
_LOW_OPS = frozenset({"==", "===", "!=", "!==", "<>", "<", ">", "<=", ">=", "<=>", "&&", "||"})
_ARITH_OPS = frozenset({"+", "-", "*", "/", "%", "**", "<<", ">>", "&", "|", "^"})
_REQUEST_BAGS = frozenset({"query", "request", "cookies", "headers", "attributes", "files", "server", "input", "json"})
_REQUEST_METHODS = frozenset(
    {"input", "get", "query", "post", "all", "only", "except", "cookie", "header", "getcontent", "getquerystring"}
    | {"string", "str", "route", "json", "getqueryparams", "getparsedbody", "getcookieparams", "getheader"}
    | {
        "getrequesturi",
        "getpathinfo",
        "getrequesturl",
        "getbody",
        "param",
        "params",
        "getquery",
        "getdata",
        "get_param",
    }
    | {"get_params", "get_json_params", "get_body_params", "get_query_params", "get_header", "post_get", "get_post"}
    | {"raw_input_stream", "getparam", "getparams", "getpost", "getrawbody", "getserverparams", "getattribute"}
    | {"query_string", "has", "keys", "toarray", "allfiles", "getclientip"}
)
_STATIC_REQUEST_CLASSES = frozenset({"request", "input", "route"})

# Functions that return clean data whatever they are given, and the sink classes others clear.
CLEAN = frozenset(
    {"intval", "floatval", "doubleval", "abs", "count", "sizeof", "strlen", "mb_strlen", "boolval", "absint", "round"}
    | {"floor", "ceil", "max", "min", "md5", "sha1", "crc32", "hash", "hash_hmac", "crypt", "password_hash", "uniqid"}
    | {"time", "date", "microtime", "rand", "mt_rand", "random_int", "bin2hex", "base64_encode", "urlencode"}
    | {"rawurlencode", "number_format", "in_array", "array_key_exists", "isset", "empty", "is_numeric", "ctype_digit"}
    | {"ctype_alnum", "ctype_alpha", "is_int", "is_string", "is_array", "is_bool", "is_null", "preg_match", "strcmp"}
    | {"array_sum", "intdiv", "mt_getrandmax", "filesize", "file_exists", "is_file", "is_dir"}
    | {"random_bytes", "openssl_random_pseudo_bytes", "gettype", "get_class", "spl_object_hash", "array_key_first"}
    | {"strtotime", "checkdate", "version_compare", "password_verify", "hash_equals", "wp_create_nonce", "wp_hash"}
)
CLEARS: dict[str, frozenset[str]] = {
    "htmlspecialchars": frozenset({HTML}),
    "htmlentities": frozenset({HTML}),
    "esc_html": frozenset({HTML}),
    "esc_attr": frozenset({HTML}),
    "esc_textarea": frozenset({HTML}),
    "esc_js": frozenset({HTML}),
    "esc_url": frozenset({HTML}),
    "esc_url_raw": frozenset({HTML}),
    "wp_kses": frozenset({HTML}),
    "wp_kses_post": frozenset({HTML}),
    "wp_strip_all_tags": frozenset({HTML}),
    "strip_tags": frozenset({HTML}),
    "sanitize_text_field": frozenset({HTML}),
    "sanitize_textarea_field": frozenset({HTML}),
    "sanitize_title": frozenset({HTML, PATH}),
    "sanitize_key": frozenset({HTML, PATH, SQL}),
    "sanitize_email": frozenset({HTML}),
    "sanitize_file_name": frozenset({HTML, PATH}),
    "sanitize_html_class": frozenset({HTML, PATH}),
    "json_encode": frozenset({HTML}),
    "wp_json_encode": frozenset({HTML}),
    "e": frozenset({HTML}),
    "h": frozenset({HTML}),
    "escapeshellarg": frozenset({SHELL}),
    "escapeshellcmd": frozenset({SHELL}),
    "basename": frozenset({PATH}),
    "mysqli_real_escape_string": frozenset({SQL}),
    "mysql_real_escape_string": frozenset({SQL}),
    "mysqli_escape_string": frozenset({SQL}),
    "pg_escape_string": frozenset({SQL}),
    "pg_escape_literal": frozenset({SQL}),
    "pg_escape_identifier": frozenset({SQL}),
    "sqlite_escape_string": frozenset({SQL}),
    "addslashes": frozenset({SQL}),
    "esc_sql": frozenset({SQL}),
    "real_escape_string": frozenset({SQL}),
    "quote": frozenset({SQL}),
    "escape": frozenset({SQL}),
    "escapestring": frozenset({SQL}),
    "escape_string": frozenset({SQL}),
}
_PROPAGATE = frozenset(
    {"trim", "ltrim", "rtrim", "chop", "strtolower", "strtoupper", "mb_strtolower", "mb_strtoupper", "ucfirst"}
    | {"ucwords", "lcfirst", "substr", "mb_substr", "str_replace", "str_ireplace", "preg_replace", "sprintf"}
    | {"vsprintf", "implode", "join", "explode", "array_map", "array_values", "array_merge", "array_filter"}
    | {"array_keys", "array_slice", "array_pop", "array_shift", "current", "reset", "end", "stripslashes"}
    | {"urldecode", "rawurldecode", "base64_decode", "html_entity_decode", "htmlspecialchars_decode", "json_decode"}
    | {"unserialize", "maybe_unserialize", "serialize", "str_pad", "str_repeat", "strrev", "strstr", "strrchr"}
    | {"substr_replace", "nl2br", "wordwrap", "addcslashes", "stripcslashes", "hex2bin", "wp_unslash", "dirname"}
    | {"stripslashes_deep", "mb_convert_encoding", "iconv", "utf8_decode", "utf8_encode", "strval", "realpath"}
    | {"array_combine", "array_merge_recursive", "array_replace", "array_unique", "array_reverse", "array_diff"}
    | {"trailingslashit", "untrailingslashit", "preg_quote", "http_build_query", "parse_url", "pathinfo", "array_flip"}
    | {"stream_get_contents", "fgets", "fread", "mb_strimwidth", "strtr", "ucwords", "money_format", "array_column"}
    | {"array_walk_recursive", "str_word_count", "nl_langinfo", "sanitize_user", "urlencode_deep", "preg_split"}
    | {"htmlspecialchars_decode", "html_entity_decode", "wp_specialchars_decode", "wp_parse_args", "shortcode_atts"}
)
_REQUEST_FUNCS = frozenset({"getallheaders", "apache_request_headers"})
_FILTER_CLEAN = re.compile(
    r"^FILTER_(?:VALIDATE_(?:INT|FLOAT|BOOL|BOOLEAN|EMAIL|IP|MAC)|SANITIZE_NUMBER_(?:INT|FLOAT))$"
)
_FILTER_HTML = re.compile(r"^FILTER_(?:SANITIZE_(?:SPECIAL_CHARS|FULL_SPECIAL_CHARS|STRING|STRIPPED|ENCODED|EMAIL))$")


def best(origins: list[Origin], sink: str, *, objects: bool = False) -> Origin | None:
    """The first origin whose data no sanitizer has made safe for ``sink`` (and that is a value, not a bag)."""
    for origin in origins:
        if sink not in origin.cleared and origin.obj == objects:
            return origin
    return None


def _add(origins: list[Origin], new: list[Origin]) -> list[Origin]:
    for item in new:
        if len(origins) >= MAX_ORIGINS:
            break
        if item not in origins:
            origins.append(item)
    return origins


class Index:
    def __init__(self, tokens: list[Token], lines: list[str]) -> None:
        self.toks = tokens
        self.n = len(tokens)
        self.lines = lines
        self.steps = 0
        self.memo: dict[tuple[int, int], list[Origin]] = {}
        self.match = [-1] * self.n
        self._match_groups()
        self.scopes: list[Scope] = [Scope(0, 0, self.n, 0, False)]
        self._find_functions()
        self.scope_of = [0] * self.n
        self.bdepth = [0] * self.n
        self._sweep()
        self.binds: dict[tuple[int, str], list[Bind]] = {}
        self._collect()

    # ----- structure

    def punct(self, i: int, *values: str) -> bool:
        return 0 <= i < self.n and self.toks[i].kind == PUNCT and self.toks[i].value in values

    def name_at(self, i: int) -> str | None:
        return self.toks[i].value.lower() if 0 <= i < self.n and self.toks[i].kind == NAME else None

    def _match_groups(self) -> None:
        stack: list[int] = []
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind != PUNCT:
                continue
            if tok.value in _OPEN:
                stack.append(i)
            elif tok.value in _CLOSE and stack and toks[stack[-1]].value == _MATCH_OF[tok.value]:
                opener = stack.pop()
                self.match[opener] = i
                self.match[i] = opener

    def split(self, lo: int, hi: int, sep: str = ",") -> list[tuple[int, int]]:
        """Spans of ``lo..hi`` split at top-level ``sep`` (empty spans are dropped)."""
        out: list[tuple[int, int]] = []
        start = lo
        k = lo
        while k < hi:
            tok = self.toks[k]
            if tok.kind == PUNCT:
                if tok.value in _OPEN and self.match[k] > k:
                    k = self.match[k] + 1
                    continue
                if tok.value == sep:
                    if k > start:
                        out.append((start, k))
                    start = k + 1
            k += 1
        if hi > start:
            out.append((start, hi))
        return out

    def args(self, open_: int) -> list[tuple[int, int]]:
        close = self.match[open_]
        return self.split(open_ + 1, close) if close > open_ else []

    def expr_end(self, lo: int) -> int:
        """Token index where the expression starting at ``lo`` ends: a ``;`` or ``,`` or an unmatched closer.

        The tokens stepped over count against the work bound, so a chain of assignments that each span the rest of the
        file ends the analysis as too complex instead of taking quadratic time."""
        k = lo
        limit = min(self.n, lo + MAX_EXPR)
        toks = self.toks
        steps = 0
        end = limit
        while k < limit:
            tok = toks[k]
            steps += 1
            if tok.kind == PUNCT:
                if tok.value in _OPEN:
                    k = self.match[k] + 1 if self.match[k] > k else k + 1
                    continue
                if tok.value in (";", ",") or tok.value in _CLOSE:
                    end = k
                    break
            k += 1
        self.steps += steps
        if self.steps > MAX_STEPS:
            raise TooComplex
        return min(end, self.n)

    def _find_functions(self) -> None:
        toks = self.toks
        found: list[Scope] = []
        for i, tok in enumerate(toks):
            if tok.kind != NAME or tok.value.lower() != "function":
                continue
            prev = toks[i - 1] if i else None
            if prev is not None and (
                (prev.kind == PUNCT and prev.value in ("->", "::", "?->"))
                or (prev.kind == NAME and prev.value == "use")
            ):
                continue
            j = i + 1
            if self.punct(j, "&"):
                j += 1
            named = j < self.n and toks[j].kind == NAME
            if named:
                j += 1
            if not self.punct(j, "(") or self.match[j] < 0:
                continue
            close = self.match[j]
            k = close + 1
            if self.name_at(k) == "use" and self.punct(k + 1, "(") and self.match[k + 1] > 0:
                k = self.match[k + 1] + 1
            for _ in range(64):  # a return type
                if k >= self.n or self.punct(k, "{", ";"):
                    break
                k += 1
            if not self.punct(k, "{") or self.match[k] < 0:
                continue
            scope = Scope(0, k, self.match[k], 0, not named)
            scope.requests = self._request_params(j, close)
            found.append(scope)
        found.sort(key=lambda s: s.lo)
        for number, scope in enumerate(found, start=1):
            scope.id = number
        self.scopes.extend(found)

    def _request_params(self, open_: int, close: int) -> set[str]:
        requests: set[str] = set()
        type_names: list[str] = []
        k = open_ + 1
        while k < close:
            tok = self.toks[k]
            if tok.kind == PUNCT and tok.value in _OPEN and self.match[k] > k:
                k = self.match[k] + 1
                continue
            if tok.kind == PUNCT and tok.value == ",":
                type_names = []
            elif tok.kind == NAME:
                type_names.append(tok.value.lower())
            elif tok.kind == VAR:
                if tok.value.lower() in ("request", "req") or any("request" in name for name in type_names):
                    requests.add(tok.value)
                type_names = []
            k += 1
        return requests

    def _sweep(self) -> None:
        stack: list[Scope] = []
        pending = iter(self.scopes[1:])
        upcoming = next(pending, None)
        depth = 0
        for i, tok in enumerate(self.toks):
            while upcoming is not None and upcoming.lo == i:
                upcoming.parent = stack[-1].id if stack else 0
                stack.append(upcoming)
                upcoming = next(pending, None)
            self.scope_of[i] = stack[-1].id if stack else 0
            if tok.kind == PUNCT and tok.value == "{":
                depth += 1
            self.bdepth[i] = depth
            if tok.kind == PUNCT and tok.value == "}" and depth:
                depth -= 1
            while stack and stack[-1].hi == i:
                stack.pop()

    # ----- bindings

    def _bind(self, scope: int, name: str, bind: Bind) -> None:
        self.binds.setdefault((scope, name), []).append(bind)

    def _collect(self) -> None:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind == VAR:
                if i and toks[i - 1].kind == PUNCT and toks[i - 1].value in ("->", "?->", "::", "$"):
                    continue
                self._assignment(i)
            elif tok.kind == NAME:
                word = tok.value.lower()
                if word == "foreach" and self.punct(i + 1, "("):
                    self._foreach(i)
                elif word == "list" and self.punct(i + 1, "(") and self.match[i + 1] > 0:
                    self._destructure(i, i + 1)
            elif tok.kind == PUNCT and tok.value == "[" and self.match[i] > 0 and self.punct(self.match[i] + 1, "="):
                before = toks[i - 1] if i else None
                if before is None or (before.kind == PUNCT and before.value in (";", "{", "}", "(", ",", "=>")):
                    self._destructure(i, i)

    def _assignment(self, i: int) -> None:
        toks = self.toks
        name = toks[i].value
        definite = True
        renamed = False
        k = i + 1
        while k < self.n:
            if self.punct(k, "[") and self.match[k] > k:
                k = self.match[k] + 1
                definite = False
            elif (
                self.punct(k, "->", "?->")
                and k + 1 < self.n
                and toks[k + 1].kind == NAME
                and not self.punct(k + 2, "(")
            ):
                if name == "this" and not renamed and definite:
                    name = f"this->{toks[k + 1].value}"
                    renamed = True
                else:
                    definite = False
                k += 2
            else:
                break
        if k >= self.n or toks[k].kind != PUNCT or toks[k].value not in _ASSIGN_OPS:
            return
        lo = k + 1
        if self.punct(lo, "&"):
            lo += 1
        bind = Bind(i, self.bdepth[i], lo, self.expr_end(lo), definite and toks[k].value == "=")
        self._bind(self.scope_of[i], name, bind)

    def _foreach(self, i: int) -> None:
        close = self.match[i + 1]
        if close < 0:
            return
        k = i + 2
        while k < close:
            if self.punct(k, "(", "[", "{") and self.match[k] > k:
                k = self.match[k] + 1
                continue
            if self.name_at(k) == "as":
                break
            k += 1
        else:
            return
        subject = (i + 2, k)
        for j in range(k + 1, close):
            if self.toks[j].kind == VAR and not (j and self.punct(j - 1, "->", "::")):
                self._bind(self.scope_of[j], self.toks[j].value, Bind(j, self.bdepth[i], subject[0], subject[1], True))

    def _destructure(self, start: int, open_: int) -> None:
        close = self.match[open_]
        eq = close + 1
        if not self.punct(eq, "="):
            return
        lo = eq + 1
        hi = self.expr_end(lo)
        for j in range(open_ + 1, close):
            if self.toks[j].kind == VAR and not (j and self.punct(j - 1, "->", "::")):
                self._bind(self.scope_of[j], self.toks[j].value, Bind(j, self.bdepth[start], lo, hi, False))

    def effective(self, name: str, pos: int) -> list[Bind]:
        """The assignments that may supply the value of variable ``name`` at token ``pos``, latest first."""
        out: list[Bind] = []
        depth = self.bdepth[pos]
        sid = self.scope_of[pos]
        while True:
            for bind in reversed(self.binds.get((sid, name), ())[-MAX_BINDINGS * 4 :]):
                if bind.pos >= pos or bind.lo <= pos < bind.hi:  # later, or the assignment this very use sits in
                    continue
                out.append(bind)
                self.steps += 1
                if bind.definite and bind.depth <= depth:
                    return out
                if len(out) >= MAX_BINDINGS:
                    return out
            scope = self.scopes[sid]
            if not scope.closure or sid == 0:
                return out
            sid = scope.parent

    def is_request_var(self, name: str, pos: int) -> bool:
        sid = self.scope_of[pos]
        while True:
            scope = self.scopes[sid]
            if name in scope.requests:
                return True
            if not scope.closure or sid == 0:
                return False
            sid = scope.parent

    # ----- taint

    def taint(self, lo: int, hi: int, depth: int = 0) -> list[Origin]:
        """Origins of request data in the expression ``lo..hi`` (token indexes)."""
        if lo >= hi or depth > MAX_DEPTH:
            return []
        key = (lo, hi)
        cached = self.memo.get(key)
        if cached is not None:
            return cached
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise TooComplex
        result = self._span(lo, hi, depth)
        self.memo[key] = result
        return result

    def _top_level(self, lo: int, hi: int) -> tuple[list[int], list[int], list[int], bool, bool]:
        """Positions of top-level ``?``, ``??`` and ``.``, and whether a comparison or arithmetic operator occurs."""
        questions: list[int] = []
        coalesce: list[int] = []
        dots: list[int] = []
        low = arith = False
        k = lo
        toks = self.toks
        while k < hi:
            tok = toks[k]
            if tok.kind == PUNCT:
                value = tok.value
                if value in _OPEN and self.match[k] > k:
                    k = self.match[k] + 1
                    continue
                if value == "?":
                    questions.append(k)
                elif value == "??":
                    coalesce.append(k)
                elif value == ".":
                    dots.append(k)
                elif value in _LOW_OPS:
                    low = True
                elif value in _ARITH_OPS and k > lo:
                    arith = True
            elif tok.kind == NAME and tok.value.lower() in _LOW_NAMES and k > lo:
                low = True
            k += 1
        return questions, coalesce, dots, low, arith

    def _span(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        while lo < hi and self.punct(lo, "@", "&"):
            lo += 1
        if lo >= hi:
            return []
        first = toks[lo]
        if first.kind == PUNCT and first.value in ("!", "-", "+", "~"):
            return []
        if first.kind == NAME and first.value.lower() in ("new", "clone", "function", "fn", "static"):
            return []
        if first.kind == VAR and self.punct(lo + 1, "=") and hi > lo + 2:
            return self.taint(lo + 2, hi, depth + 1)
        questions, coalesce, dots, low, arith = self._top_level(lo, hi)
        if questions:
            return self._ternary(lo, hi, questions[0], depth)
        if coalesce:
            origins: list[Origin] = []
            _add(origins, self.taint(lo, coalesce[0], depth + 1))
            return _add(origins, self.taint(coalesce[0] + 1, hi, depth + 1))
        if low:
            return []
        if dots:
            origins = []
            bounds = [lo - 1, *dots, hi]
            for a, b in pairwise(bounds):
                _add(origins, self.taint(a + 1, b, depth + 1))
            return origins
        if arith:
            return []
        return self._primary(lo, hi, depth)

    def _ternary(self, lo: int, hi: int, question: int, depth: int) -> list[Origin]:
        origins: list[Origin] = []
        if self.punct(question + 1, ":"):  # ?:
            _add(origins, self.taint(lo, question, depth + 1))
            return _add(origins, self.taint(question + 2, hi, depth + 1))
        nesting = 0
        k = question + 1
        while k < hi:
            tok = self.toks[k]
            if tok.kind == PUNCT:
                if tok.value in _OPEN and self.match[k] > k:
                    k = self.match[k] + 1
                    continue
                if tok.value == "?":
                    nesting += 1
                elif tok.value == ":":
                    if nesting == 0:
                        _add(origins, self.taint(question + 1, k, depth + 1))
                        return _add(origins, self.taint(k + 1, hi, depth + 1))
                    nesting -= 1
            k += 1
        return _add(origins, self.taint(question + 1, hi, depth + 1))

    def _primary(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        tok = toks[lo]
        if tok.kind in (STR, NUM):
            return []
        if tok.kind == ISTR:
            return self._interpolated(tok, lo)
        if tok.kind == VAR:
            return self._variable(lo, hi, depth)
        if tok.kind == NAME:
            return self._name(lo, hi, depth)
        if tok.kind == PUNCT and tok.value == "(" and self.match[lo] > lo:
            close = self.match[lo]
            if lo + 2 == close and toks[lo + 1].kind == NAME and toks[lo + 1].value.lower() in _ALL_CASTS:
                return [] if toks[lo + 1].value.lower() in _CLEAN_CASTS else self.taint(close + 1, hi, depth + 1)
            inner = self.taint(lo + 1, close, depth + 1)
            return self._postfix(inner, close + 1, hi, depth)
        if tok.kind == PUNCT and tok.value == "[" and self.match[lo] > lo:
            close = self.match[lo]
            origins = self._elements(lo + 1, close, depth)
            return self._postfix(origins, close + 1, hi, depth)
        return []

    def _elements(self, lo: int, hi: int, depth: int) -> list[Origin]:
        origins: list[Origin] = []
        for a, b in self.split(lo, hi):
            for c, d in self.split(a, b, "=>") or [(a, b)]:
                _add(origins, self.taint(c, d, depth + 1))
        return origins

    def _interpolated(self, tok: Token, pos: int) -> list[Origin]:
        origins: list[Origin] = []
        for name in tok.vars:
            if name in _SUPERGLOBALS:
                _add(origins, [self._source(f"${name}", tok.line)])
            elif name == "_SERVER" and re.search(
                r"_SERVER\[\s*['\"]?(?:QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO|HTTP_)", tok.value
            ):
                _add(origins, [self._source("$_SERVER", tok.line)])
            else:
                _add(origins, self._request_member(name, tok, pos))
                _add(origins, self._bound(name, pos))
        return origins

    def _request_member(self, name: str, tok: Token, pos: int) -> list[Origin]:
        """``"$request->name"`` and ``"{$request->input('x')}"`` inside a string: values of a request object."""
        if not self.is_request_var(name, pos):
            return []
        for match in re.finditer(rf"\$\{{?\$?{re.escape(name)}->(\w+)(\()?", tok.value):
            if match.group(1).lower() in _REQUEST_METHODS or match.group(2) is None:
                return [self._source(f"${name}", tok.line)]
        return []

    def _source(self, label: str, line: int, *, obj: bool = False) -> Origin:
        return Origin(label, line, frozenset(), obj, (TraceStep(line, f"{label} (source)"),))

    def _bound(self, name: str, pos: int) -> list[Origin]:
        origins: list[Origin] = []
        for bind in self.effective(name, pos):
            for origin in self.taint(bind.lo, bind.hi, 1):
                step = TraceStep(self.toks[bind.pos].line, f"assigned to ${name.removeprefix('this->')}")
                trace = origin.trace if len(origin.trace) >= MAX_TRACE else (*origin.trace, step)
                _add(origins, [Origin(origin.label, origin.line, origin.cleared, origin.obj, trace)])
        return origins

    def _variable(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        tok = toks[lo]
        name = tok.value
        k = lo + 1
        if name in _SUPERGLOBALS:
            return self._postfix([self._source(f"${name}", tok.line)], k, hi, depth)
        if name == "_SERVER":
            if (
                self.punct(k, "[")
                and k + 1 < self.n
                and toks[k + 1].kind == STR
                and _SERVER_FIELD.match(toks[k + 1].value)
            ):
                return self._postfix([self._source("$_SERVER", tok.line)], self.match[k] + 1, hi, depth)
            return []
        if name == "_FILES":
            if self.punct(k, "[") and self.match[k] > 0 and self.punct(self.match[k] + 1, "["):
                second = self.match[k] + 1
                if second + 1 < self.n and toks[second + 1].kind == STR and toks[second + 1].value == "name":
                    return self._postfix([self._source("$_FILES name", tok.line)], self.match[second] + 1, hi, depth)
            return []
        if name == "this" and self.punct(k, "->") and k + 1 < self.n and toks[k + 1].kind == NAME:
            prop = toks[k + 1].value
            if prop.lower() in ("request", "input") and not self.punct(k + 2, "("):
                return self._postfix([self._source(f"$this->{prop}", tok.line, obj=True)], k + 2, hi, depth)
            if not self.punct(k + 2, "("):
                return self._postfix(self._bound(f"this->{prop}", lo), k + 2, hi, depth)
            return []
        if self.is_request_var(name, lo):
            return self._postfix([self._source(f"${name}", tok.line, obj=True)], k, hi, depth)
        return self._postfix(self._bound(name, lo), k, hi, depth)

    def _postfix(self, origins: list[Origin], k: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        while k < hi and origins:
            if self.punct(k, "["):
                k = self.match[k] + 1 if self.match[k] > k else hi
            elif self.punct(k, "->", "?->") and k + 1 < hi and toks[k + 1].kind == NAME:
                member = toks[k + 1].value
                if self.punct(k + 2, "("):
                    if member.lower() not in _REQUEST_METHODS:
                        return []
                    origins = [Origin(o.label, o.line, o.cleared, False, o.trace) for o in origins]
                    k = self.match[k + 2] + 1 if self.match[k + 2] > k else hi
                else:
                    bag = member.lower() in _REQUEST_BAGS
                    origins = [Origin(o.label, o.line, o.cleared, o.obj and bag, o.trace) for o in origins]
                    k += 2
            else:
                if k < hi and self.punct(k, "::", "("):
                    return []
                break
        return origins

    def _name(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        tok = toks[lo]
        word = tok.value.lstrip("\\").lower()
        word = word.rsplit("\\", 1)[-1]
        after = lo + 1
        if self.punct(after, "::") and after + 2 < self.n and toks[after + 1].kind == NAME:
            method = toks[after + 1].value.lower()
            if word in _STATIC_REQUEST_CLASSES and method in _REQUEST_METHODS and self.punct(after + 2, "("):
                end = self.match[after + 2] + 1
                return self._postfix(
                    [self._source(f"{tok.value}::{toks[after + 1].value}()", tok.line)], end, hi, depth
                )
            return []
        if not self.punct(after, "(") or self.match[after] < 0:
            return []
        close = self.match[after]
        args = self.args(after)
        origins = self._call(word, tok, args, (after, close), depth)
        return self._postfix(origins, close + 1, hi, depth)

    def _call(
        self, word: str, tok: Token, args: list[tuple[int, int]], span: tuple[int, int], depth: int
    ) -> list[Origin]:
        open_, close = span
        toks = self.toks
        if word in _REQUEST_FUNCS:
            return [self._source(f"{word}()", tok.line)]
        if word == "request":  # Laravel's helper: request('x') is a value, request() the request object
            return [self._source("request()", tok.line, obj=not args)]
        if word in ("filter_input", "filter_input_array"):
            names = {t.value for t in toks[open_ + 1 : close] if t.kind == NAME}
            if any(_FILTER_CLEAN.match(n) for n in names):
                return []
            origin = self._source(f"{word}()", tok.line)
            if any(_FILTER_HTML.match(n) for n in names):
                origin = Origin(origin.label, origin.line, frozenset({HTML}), False, origin.trace)
            return [origin]
        if word in ("file_get_contents", "fopen") and any(
            t.kind == STR and t.value.lower() == "php://input" for t in toks[open_ + 1 : close]
        ):
            return [self._source("php://input", tok.line)]
        if word in CLEAN:
            return []
        if word == "filter_var":
            names = {t.value for t in toks[open_ + 1 : close] if t.kind == NAME}
            if any(_FILTER_CLEAN.match(n) for n in names):
                return []
            clears = frozenset({HTML}) if any(_FILTER_HTML.match(n) for n in names) else frozenset()
            return self._cleared(self._union(args[:1], depth), clears)
        if word in CLEARS:
            return self._cleared(self._union(args[:1] if word != "str_replace" else args, depth), CLEARS[word])
        if word in _PROPAGATE:
            return self._union(args, depth)
        if word in ("array", "compact"):
            return self._elements(open_ + 1, close, depth) if word == "array" else []
        return []

    def _union(self, spans: list[tuple[int, int]], depth: int) -> list[Origin]:
        origins: list[Origin] = []
        for a, b in spans:
            _add(origins, self.taint(a, b, depth + 1))
        return origins

    @staticmethod
    def _cleared(origins: list[Origin], classes: frozenset[str]) -> list[Origin]:
        return [Origin(o.label, o.line, o.cleared | classes, o.obj, o.trace) for o in origins]
