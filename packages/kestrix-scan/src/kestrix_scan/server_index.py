# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A structural index over Go, Java, Kotlin, C# and Ruby tokens: the matcher the ``go.*``, ``java.*``, ``cs.*`` and
``rb.*`` rules are written against.

There is no syntax tree. The index knows the matching bracket of every ``(``, ``[`` and ``{``; the functions of a file
(Go ``func``, Java and C# methods and constructors, Kotlin ``fun``, Ruby ``def`` ... ``end`` found by indentation) with
their parameters; and the assignments to each local name (``=``, ``:=``, ``+=``, ``||=``, ``val``/``var``, Go's
``a, b :=``, ``for ... in``/``:``/``range``, Ruby block parameters ``list.each do |x|``, and appends such as
``sb.append(x)``, ``b.WriteString(x)`` or ``sql << x``). Go function literals share their parent's names.

**Taint** stays inside one function; it never crosses into a called function. Sources:

- **Go:** a parameter of type ``*http.Request`` (``FormValue``, ``URL``, ``Header``, ``Body`` ...), a gin, echo,
  fiber, chi or Gitea-style context (``Query``, ``Param``, ``PostForm``, ``FormValue``, ``FormString`` ...), and
  ``mux.Vars``/``chi.URLParam``.
- **Java and Kotlin:** a parameter whose type names a ``Request`` (``getParameter``, ``getHeader``, ``getQueryString``,
  ``getInputStream`` ...), a parameter annotated ``@RequestParam``, ``@PathVariable``, ``@RequestBody``,
  ``@RequestHeader``, ``@CookieValue``, ``@QueryParam``, ``@PathParam``, ``@FormParam``, ``@HeaderParam`` or Stapler's
  ``@QueryParameter``, and Ktor's ``call.parameters``, ``call.request.queryParameters`` and ``call.receive*()``.
- **C#:** ``Request`` (``Query``, ``Form``, ``QueryString``, ``Headers``, ``Cookies``, ``Body``, ``Path`` and the
  indexer), ``HttpContext.Request``, a parameter of type ``HttpRequest``/``HttpContext``, and string parameters of
  ASP.NET actions (bound with ``[FromQuery]``, ``[FromForm]``, ``[FromRoute]``, ``[FromBody]``, ``[FromHeader]``, or of a
  public method with an ``[Http*]``/``[Route]`` attribute or in a class that derives from ``Controller``).
- **Ruby (Rails, Sinatra):** ``params``, ``cookies`` and ``request`` (``params``, ``query_string``, ``body``,
  ``raw_post``, ``headers``, ``env``, ``url``, ``path``, ``referer`` ...).

Taint flows through assignments, ``+`` concatenation, interpolated strings, ternaries, ``??``/``?:``/Ruby ``||``,
subscripts, members and calls on a tainted value, and the formatting and joining functions in ``_PROPAGATE``
(``fmt.Sprintf``, ``String.format``, ``string.Format``, ``String.join``, ``Path.Combine``, ``filepath.Join`` ...). Every
other call returns clean data. Comparisons, arithmetic and numeric parameter types give clean values; a call of a
method in ``_CLEAN_METHODS`` on a tainted value (``length()``, ``to_i``, ``Count`` ...) makes it clean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import TraceStep
from .php_index import Origin, TooComplex
from .php_tokens import ISTR, NAME, NUM, PUNCT, SHELL, STR, Token

MAX_DEPTH = 40
MAX_STEPS = 3_000_000
MAX_EXPR = 8192
MAX_BINDINGS = 64
MAX_ORIGINS = 4
MAX_TRACE = 8

_OPEN = frozenset("([{")
_CLOSE = frozenset(")]}")
_MATCH_OF = {")": "(", "]": "[", "}": "{"}
NEWLINE_LANGUAGES = frozenset({"go", "kotlin", "ruby"})
_CONTINUE_AFTER = frozenset(
    {"+", "-", "*", "/", "%", ".", ",", "(", "[", "{", "=", ":=", "&&", "||", "?", ":", "?:", "??", "<<", "|", "&"}
    | {"..", "->", "=>", "+=", "||=", "?.", "&.", "!", "==", "!=", "<", ">", "<=", ">="}
)
_CONTINUE_BEFORE = frozenset({".", "?.", "&.", "+", "&&", "||", "?", ":", "?:", "??", ")", "]", "}", "|", "*", "/"})
_RUBY_STOP_WORDS = frozenset({"if", "unless", "while", "until", "rescue", "do", "then", "end"})
_C_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "synchronized", "using", "lock", "foreach", "fixed", "when", "else"}
    | {"try", "return", "new", "typeof", "sizeof", "nameof", "checked", "unchecked", "default", "throw", "do", "in"}
    | {"super", "this", "base", "await", "assert", "is", "as", "where", "get", "set", "init", "select", "from"}
)
_NUMERIC_TYPES = frozenset(
    {"int", "long", "short", "byte", "integer", "boolean", "bool", "double", "float", "decimal", "uuid", "guid"}
    | {
        "char",
        "uint",
        "ulong",
        "ushort",
        "sbyte",
        "datetime",
        "datetimeoffset",
        "localdate",
        "localdatetime",
        "instant",
    }
    | {"int32", "int64", "int16", "uint32", "uint64", "cancellationtoken", "timespan", "biginteger", "bigdecimal"}
)
_ANNOTATED_SOURCES = frozenset(
    {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue", "MatrixVariable", "RequestPart"}
    | {"QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam", "QueryParameter", "QueryValue", "Header"}
    | {"FromQuery", "FromForm", "FromRoute", "FromBody", "FromHeader"}
)
_MAPPING_ANNOTATIONS = re.compile(
    r"^(?:Get|Post|Put|Delete|Patch|Request)Mapping$|^Http(?:Get|Post|Put|Delete|Patch)$|^Route$"
)
_STRINGISH = re.compile(
    r"(?i)^(?:string|string\[\]|list<string>|ienumerable<string>|iformfile|multipartfile|object|dynamic|jobject|map)"
)

# Request objects: which members give request data. Values here are what a member access or call returns.
_REQUEST_TYPES: dict[str, re.Pattern[str]] = {
    "go": re.compile(
        r"\bhttp\.Request\b|\bgin\.Context\b|\becho\.Context\b|\bfiber\.Ctx\b|\*context\.\w*Context\b|\bmacaron\.Context\b"
    ),
    "java": re.compile(r"Request\b(?!\w)"),
    "kotlin": re.compile(r"Request\b(?!\w)|\bApplicationCall\b"),
    "csharp": re.compile(r"\bHttpRequest\b|\bHttpContext\b"),
}
_REQUEST_MEMBERS: dict[str, frozenset[str]] = {
    "go": frozenset(
        {"FormValue", "PostFormValue", "Form", "PostForm", "MultipartForm", "URL", "Header", "Body", "Cookie"}
        | {
            "Cookies",
            "FormFile",
            "PathValue",
            "RequestURI",
            "Referer",
            "UserAgent",
            "Query",
            "DefaultQuery",
            "GetQuery",
        }
        | {"QueryArray", "QueryMap", "Param", "Params", "DefaultPostForm", "GetPostForm", "PostFormArray", "FormString"}
        | {"FormStrings", "FormTrim", "QueryParam", "QueryParams", "QueryString", "PathParam", "GetHeader", "Get"}
        | {"GetRawData", "ParamsInt64", "ParamsEscape", "URLParam", "BodyParser", "AllParams", "Queries"}
    ),
    "java": frozenset(
        {"getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getHeader", "getHeaders"}
        | {
            "getQueryString",
            "getRequestURI",
            "getRequestURL",
            "getPathInfo",
            "getCookies",
            "getInputStream",
            "getReader",
        }
        | {
            "getPart",
            "getParts",
            "getRestOfPath",
            "getOriginalRestOfPath",
            "getSubmittedForm",
            "bindJSON",
            "getQueryParams",
        }
        | {
            "getURI",
            "getUri",
            "getBody",
            "queryParam",
            "queryParams",
            "pathParam",
            "formParam",
            "header",
            "body",
            "param",
        }
        | {"parameters", "queryParameters", "receiveParameters", "receiveText", "receive", "receiveMultipart", "uri"}
        | {"queryString", "cookies", "headers", "getParameterOrNull", "getFileName", "getOriginalFilename"}
    ),
    "csharp": frozenset(
        {"Query", "QueryString", "Form", "Params", "Headers", "Cookies", "Body", "Path", "RawUrl", "Url", "Files"}
        | {"RouteValues", "InputStream", "ServerVariables", "PathInfo", "FilePath", "UrlReferrer", "UserAgent"}
    ),
    "ruby": frozenset(
        {"params", "query_parameters", "request_parameters", "parameters", "path_parameters", "query_string", "body"}
        | {"raw_post", "headers", "env", "url", "path", "fullpath", "original_fullpath", "original_url", "referer"}
        | {"referrer", "user_agent", "cookies", "cookie_jar", "GET", "POST", "path_info", "request_uri"}
    ),
}
_REQUEST_MEMBERS["kotlin"] = _REQUEST_MEMBERS["java"]
_OBJECT_MEMBERS: dict[str, frozenset[str]] = {  # members that are themselves request objects
    "go": frozenset({"Req", "Request"}),
    "java": frozenset({"request", "getRequest"}),
    "kotlin": frozenset({"request", "getRequest"}),
    "csharp": frozenset({"Request", "HttpContext"}),
    "ruby": frozenset({"request"}),
}
_ROOT_OBJECTS: dict[str, frozenset[str]] = {  # names that are request objects unless the code assigns them
    "go": frozenset(),
    "java": frozenset(),
    "kotlin": frozenset({"call"}),
    "csharp": frozenset({"Request", "HttpContext"}),
    "ruby": frozenset({"request"}),
}
_ROOT_VALUES: dict[str, frozenset[str]] = {  # names that are request data unless the code assigns them
    "ruby": frozenset({"params", "cookies"}),
}
_WRITER_TYPES = re.compile(r"ResponseWriter\b|HttpServletResponse\b|ServletResponse\b|StaplerResponse\w*\b")
_ARCHIVE_ENTRY = re.compile(r"(?i)^(?:zip|tar|jar|archive)?_?(?:entry|header|hdr)$")
_ARCHIVE_MEMBERS = frozenset({"FullName", "getName", "Name", "name", "full_name", "Linkname", "getLinkName"})
_UPLOAD = re.compile(r"(?i)file|upload|attachment|posted|part")
_UPLOAD_MEMBERS = frozenset({"Filename", "getOriginalFilename", "getSubmittedFileName", "original_filename", "FileName"})
_SOURCE_CALLS = frozenset({"mux.Vars", "chi.URLParam", "chi.URLParamFromCtx", "pat.Param", "vars.Get"})

# Calls that pass their arguments' data on, by the callee's last name; every other call returns clean data.
_PROPAGATE: dict[str, frozenset[str]] = {
    "go": frozenset(
        {"Sprintf", "Sprint", "Sprintln", "Join", "TrimSpace", "Trim", "TrimLeft", "TrimRight", "TrimPrefix"}
        | {"TrimSuffix", "ToLower", "ToUpper", "Title", "Replace", "ReplaceAll", "Split", "Fields", "Repeat", "Clean"}
        | {"Abs", "Unescape", "QueryUnescape", "PathUnescape", "DecodeString", "Dir", "Ext", "Errorf"}
        | {"string", "Join", "SplitN", "Map", "NewReader", "ReadAll", "Concat", "Expand", "ExpandEnv", "ToValidUTF8"}
    ),
    "java": frozenset(
        {"format", "formatted", "join", "concat", "valueOf", "toString", "get", "of", "decode", "copyOf", "asList"}
        | {"trim", "strip", "replace", "replaceAll", "substring", "toLowerCase", "toUpperCase", "append", "resolve"}
        | {"normalize", "getCanonicalPath", "getAbsolutePath", "toPath", "toFile", "toURI", "create", "parse", "listOf"}
        | {"mutableListOf", "joinToString", "buildString", "plus", "unescape", "unescapeJava", "toArray", "split"}
    ),
    "csharp": frozenset(
        {"Format", "Concat", "Join", "Combine", "GetFullPath", "Trim", "TrimStart", "TrimEnd", "Replace", "Substring"}
        | {"ToLower", "ToUpper", "ToLowerInvariant", "ToUpperInvariant", "ToString", "UrlDecode", "UnescapeDataString"}
        | {"Append", "AppendFormat", "AppendLine", "Insert", "Split", "GetString", "ReadToEnd", "ReadToEndAsync"}
        | {"FromBase64String", "Normalize", "First", "FirstOrDefault", "Single", "SingleOrDefault", "ElementAt"}
    ),
    "ruby": frozenset(
        {"join", "format", "sprintf", "expand_path", "unescape", "decode", "decode64", "strip", "gsub", "sub"}
        | {"downcase", "upcase", "squish", "chomp", "to_s", "to_sym", "first", "last", "dig", "fetch", "values"}
        | {"require", "permit", "slice", "except", "merge", "to_h", "to_unsafe_h", "presence", "underscore"}
        | {
            "camelize",
            "classify",
            "pluralize",
            "singularize",
            "titleize",
            "constantize",
            "safe_constantize",
            "url_decode",
        }
    ),
}
_PROPAGATE["kotlin"] = _PROPAGATE["java"]
_GO_PROPAGATING_PACKAGES = frozenset({"strings", "fmt", "filepath", "path", "url", "bytes", "base64"})
_GO_SANITIZERS = frozenset(
    {"Base", "EscapeString", "QueryEscape", "PathEscape", "HTMLEscapeString", "JSEscapeString", "QuoteMeta", "Quote"}
    | {"EncodeToString", "Contains", "HasPrefix", "HasSuffix", "Index", "Count", "Compare", "EqualFold", "IsAbs", "Match"}
)
# Methods that make a tainted receiver clean (lengths, tests, numbers), by language family.
_CLEAN_METHODS = frozenset(
    {"length", "size", "isEmpty", "isBlank", "equals", "equalsIgnoreCase", "hashCode", "contains", "startsWith"}
    | {"endsWith", "matches", "indexOf", "compareTo", "count", "Count", "Length", "Any", "Contains", "StartsWith"}
    | {"EndsWith", "Equals", "IsNullOrEmpty", "GetHashCode", "CompareTo", "IndexOf", "to_i", "to_f", "to_r"}
    | {"to_c", "present?", "blank?", "nil?", "empty?", "include?", "length", "size", "any?", "start_with?"}
    | {"end_with?", "match?", "is_a?", "kind_of?", "hash", "Len", "HasPrefix", "HasSuffix", "EqualFold", "Atoi"}
    | {
        "ParseInt",
        "ParseBool",
        "ParseFloat",
        "ParseUint",
        "toInt",
        "toLong",
        "toIntOrNull",
        "toLongOrNull",
        "isNotEmpty",
    }
    | {"isNotBlank", "isNullOrEmpty", "isNullOrBlank", "intValue", "longValue", "booleanValue", "Exists", "has_key?"}
    | {"key?", "zero?", "positive?", "to_bool", "Parse", "TryParse", "ParseExact", "ToInt32", "ToInt64", "ToBoolean"}
    | {"getName", "Name", "getSize", "Size", "getContentType", "ContentType", "getLength", "ContentLength"}
)
_NUMERIC_CALLS = frozenset(
    {"parseInt", "parseLong", "parseDouble", "parseBoolean", "Atoi", "ParseInt", "ParseUint", "ParseFloat", "Parse"}
    | {"TryParse", "ToInt32", "ToInt64", "ToDouble", "ToBoolean", "Integer", "Float", "fromString", "toInt"}
)
_PROPAGATE_NEW = frozenset(
    {"String", "StringBuilder", "StringBuffer", "File", "FileInputStream", "FileOutputStream", "FileReader", "URL"}
    | {"URI", "Uri", "FileInfo", "DirectoryInfo", "FileStream", "StreamReader", "StreamWriter", "Path", "StringReader"}
    | {"InputSource", "ByteArrayInputStream", "InputStreamReader", "BufferedReader"}
)
_LOW_OPS = frozenset({"==", "!=", "&&", "===", "=~", "!~", "<=", ">=", "<=>"})
_LOW_NAMES = frozenset({"instanceof", "is", "and", "or", "not", "in"})
_ARITH = frozenset({"-", "*", "/", "%", "<<", ">>", "&", "|", "^"})
_APPENDS = frozenset(
    {"append", "Append", "AppendFormat", "AppendLine", "WriteString", "Write", "insert", "Insert", "concat", "push"}
    | {"add", "Add", "addAll", "AddRange", "put", "Put", "set", "Set", "Fprintf"}
)
_BLOCK_ITERATORS = frozenset(
    {"each", "map", "each_with_index", "select", "collect", "flat_map", "each_pair", "each_value", "each_key", "filter"}
    | {
        "reject",
        "find",
        "detect",
        "each_with_object",
        "sort_by",
        "group_by",
        "forEach",
        "ForEach",
        "let",
        "also",
        "apply",
    }
)


@dataclass(slots=True)
class Scope:
    id: int
    lo: int  # token index of the body's first token
    hi: int  # token index of the body's last token
    parent: int
    closure: bool  # a Go function literal: names of the enclosing function are visible
    params: dict[str, str] = field(default_factory=dict)  # name -> "object" (a request) or "value" (request data)


@dataclass(frozen=True, slots=True)
class Bind:
    pos: int
    depth: int
    lo: int
    hi: int
    definite: bool


def _add(origins: list[Origin], new: list[Origin]) -> list[Origin]:
    for item in new:
        if len(origins) >= MAX_ORIGINS:
            break
        if item not in origins:
            origins.append(item)
    return origins


class Index:
    def __init__(self, tokens: list[Token], lines: list[str], language: str) -> None:
        self.toks = tokens
        self.n = len(tokens)
        self.lines = lines
        self.lang = language
        self.family = "java" if language == "kotlin" else language
        self.steps = 0
        self.memo: dict[tuple[int, int], list[Origin]] = {}
        self.match = [-1] * self.n
        self._match_groups()
        self.depth = self._depths()
        self.scopes: list[Scope] = [Scope(0, 0, self.n, 0, False)]
        self.controller = language == "csharp" and any(
            t.kind == NAME and t.value in ("Controller", "ControllerBase", "ApiController") for t in tokens
        )
        if language == "ruby":
            self._ruby_functions()
        else:
            self._c_functions()
        self.scope_of = [0] * self.n
        self._sweep()
        self.binds: dict[tuple[int, str], list[Bind]] = {}
        self._collect()

    # ----- structure

    def punct(self, i: int, *values: str) -> bool:
        return 0 <= i < self.n and self.toks[i].kind == PUNCT and self.toks[i].value in values

    def name(self, i: int) -> str | None:
        return self.toks[i].value if 0 <= i < self.n and self.toks[i].kind == NAME else None

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

    def _depths(self) -> list[int]:
        """Nesting depth of each token: brace depth, or for Ruby the indentation of its line (blocks end with ``end``)."""
        if self.lang == "ruby":
            out = []
            for tok in self.toks:
                line = self.lines[tok.line - 1] if 0 < tok.line <= len(self.lines) else ""
                out.append(len(line) - len(line.lstrip(" \t")))
            return out
        depth = 0
        out = [0] * self.n
        for i, tok in enumerate(self.toks):
            if tok.kind == PUNCT and tok.value == "{":
                depth += 1
            out[i] = depth
            if tok.kind == PUNCT and tok.value == "}" and depth:
                depth -= 1
        return out

    def args(self, open_: int) -> list[tuple[int, int]]:
        close = self.match[open_]
        return self.split(open_ + 1, close) if close > open_ else []

    def split(self, lo: int, hi: int, sep: str = ",") -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        start = k = lo
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

    def _breaks(self, k: int) -> bool:
        """For newline languages: does a new statement start at token ``k`` (on a later line than ``k - 1``)?"""
        prev, tok = self.toks[k - 1], self.toks[k]
        if tok.line <= prev.end_line:
            return False
        if prev.kind == PUNCT and prev.value in _CONTINUE_AFTER:
            return False
        if self.lang == "ruby" and prev.kind == NAME and prev.value in ("and", "or", "not"):
            return False
        return not (tok.kind == PUNCT and tok.value in _CONTINUE_BEFORE)

    def expr_end(self, lo: int) -> int:
        """Token index where the expression starting at ``lo`` ends (counted against the work bound)."""
        k = lo
        limit = min(self.n, lo + MAX_EXPR)
        toks = self.toks
        newline = self.lang in NEWLINE_LANGUAGES
        end = limit
        while k < limit:
            tok = toks[k]
            self.steps += 1
            if k > lo and newline and self._breaks(k):
                end = k
                break
            if tok.kind == PUNCT:
                if tok.value in _OPEN and self.match[k] > k:
                    k = self.match[k] + 1
                    continue
                if tok.value in (";", ",") or tok.value in _CLOSE:
                    end = k
                    break
                if tok.value == "{" and self.lang != "go":  # a block or lambda body after the expression
                    end = k
                    break
            elif self.lang == "ruby" and k > lo and tok.kind == NAME and tok.value in _RUBY_STOP_WORDS:
                end = k
                break
            k += 1
        if self.steps > MAX_STEPS:
            raise TooComplex
        return min(end, self.n)

    # ----- functions

    def _c_functions(self) -> None:
        toks = self.toks
        found: list[Scope] = []
        for i, tok in enumerate(toks):
            if tok.kind != PUNCT or tok.value != "(" or self.match[i] < 0:
                continue
            close = self.match[i]
            prev = toks[i - 1] if i else None
            if self.lang == "go":
                closure = prev is not None and prev.kind == NAME and prev.value == "func"
                named = (
                    prev is not None
                    and prev.kind == NAME
                    and i >= 2
                    and (self.name(i - 2) == "func" or (self.punct(i - 2, ")") and self._go_receiver(i - 2)))
                )
                if not (closure or named):
                    continue
            elif prev is None or prev.kind != NAME or prev.value in _C_KEYWORDS or self.name(i - 2) == "new":
                continue
            else:  # a Kotlin call with a trailing lambda (`get("/") { ... }`) sees the names around it
                closure = self.lang == "kotlin" and self.name(i - 2) != "fun"
            body = self._body_after(close)
            if body is None:
                continue
            scope = Scope(0, body, self.match[body], 0, closure)
            scope.params = self._params(i, close, self._annotations_before(i - 1))
            found.append(scope)
        found.sort(key=lambda s: s.lo)
        for number, scope in enumerate(found, start=1):
            scope.id = number
        self.scopes.extend(found)

    def _go_receiver(self, close: int) -> bool:
        opener = self.match[close]
        return opener > 0 and self.name(opener - 1) == "func"

    def _body_after(self, close: int) -> int | None:
        """The ``{`` of the body that follows a parameter list (past a return type, ``throws``, a Kotlin ``: Type``)."""
        k = close + 1
        for _ in range(48):
            if k >= self.n:
                return None
            tok = self.toks[k]
            if tok.kind == PUNCT and tok.value == "{":
                return k if self.match[k] > k else None
            if tok.kind == PUNCT and tok.value in (";", "=", "=>", ")", "}"):
                return None
            if tok.kind == PUNCT and tok.value in ("(", "[") and self.match[k] > k:
                k = self.match[k] + 1
                continue
            if tok.kind not in (NAME, PUNCT):
                return None
            k += 1
        return None

    def _annotations_before(self, name_pos: int) -> set[str]:
        """Annotation and attribute names written before the method name (``@GetMapping``, ``[HttpGet]``) and its
        modifiers, up to the previous statement."""
        out: set[str] = set()
        k = name_pos - 1
        for _ in range(64):
            if k < 0:
                break
            tok = self.toks[k]
            if tok.kind == PUNCT and tok.value in (";", "{", "}"):
                break
            if tok.kind == NAME and k and self.punct(k - 1, "@"):
                out.add(tok.value)
            if tok.kind == PUNCT and tok.value == "]" and self.match[k] >= 0:
                out.update(t.value for t in self.toks[self.match[k] : k] if t.kind == NAME)
                k = self.match[k] - 1
                continue
            if tok.kind == PUNCT and tok.value == ")" and self.match[k] >= 0:
                k = self.match[k] - 1
                continue
            if tok.kind == NAME and tok.value == "public":
                out.add("public")
            k -= 1
        return out

    def _params(self, open_: int, close: int, annotations: set[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        mapped = any(_MAPPING_ANNOTATIONS.match(a) for a in annotations) or (
            self.controller and "public" in annotations
        )
        types = _REQUEST_TYPES.get(self.lang)
        for lo, hi in self.split(open_ + 1, close):
            notes: set[str] = set()
            names: list[int] = []
            k = lo
            while k < hi:
                tok = self.toks[k]
                if tok.kind == PUNCT and tok.value == "@" and self.name(k + 1):
                    notes.add(self.toks[k + 1].value)
                    k += 2
                    if self.punct(k, "(") and self.match[k] > k:
                        k = self.match[k] + 1
                    continue
                if tok.kind == PUNCT and tok.value == "[" and self.match[k] > k:
                    notes.update(t.value for t in self.toks[k : self.match[k]] if t.kind == NAME)
                    k = self.match[k] + 1
                    continue
                if tok.kind == NAME:
                    names.append(k)
                k += 1
            if not names:
                continue
            at = names[0] if self.lang in ("go", "kotlin") else names[-1]
            param = self.toks[at].value
            type_names = [self.toks[j].value for j in names if j != at]
            if any(t.lower() in _NUMERIC_TYPES for t in type_names):
                continue
            if notes & _ANNOTATED_SOURCES:
                out[param] = "value"
                continue
            type_text = "".join(
                self.toks[j].value for j in range(lo, hi) if j != at and self.toks[j].kind in (NAME, PUNCT)
            ).replace("?", "")
            if types is not None and types.search(type_text):
                out[param] = "object"
            elif _WRITER_TYPES.search(type_text):
                out[param] = "writer"
            elif mapped and type_names and _STRINGISH.match("".join(type_names[-1:]).lower()):
                out[param] = "value"
        return out

    def _ruby_functions(self) -> None:
        """``def`` ... ``end``: the body ends at the first later ``end`` with the indentation of the ``def`` line."""
        toks = self.toks
        found: list[Scope] = []
        ends: dict[int, list[int]] = {}
        for i, tok in enumerate(toks):
            if tok.kind == NAME and tok.value == "end" and self._first_on_line(i):
                ends.setdefault(tok.col, []).append(i)
        for i, tok in enumerate(toks):
            if tok.kind != NAME or tok.value != "def" or not self._first_on_line(i):
                continue
            same_line = [j for j in range(i + 1, min(self.n, i + 64)) if toks[j].line == tok.line]
            inline = [j for j in same_line if toks[j].kind == NAME and toks[j].value == "end"]
            candidates = [e for e in ends.get(tok.col, ()) if e > i]
            hi = inline[-1] if inline else (candidates[0] if candidates else self.n - 1)
            found.append(Scope(len(found) + 1, i, hi, 0, False))
        self.scopes.extend(found)

    def _first_on_line(self, i: int) -> bool:
        return i == 0 or self.toks[i - 1].end_line < self.toks[i].line

    def _sweep(self) -> None:
        stack: list[Scope] = []
        pending = iter(sorted(self.scopes[1:], key=lambda s: s.lo))
        upcoming = next(pending, None)
        for i in range(self.n):
            while upcoming is not None and upcoming.lo == i:
                upcoming.parent = stack[-1].id if stack else 0
                stack.append(upcoming)
                upcoming = next(pending, None)
            self.scope_of[i] = stack[-1].id if stack else 0
            while stack and stack[-1].hi == i:
                stack.pop()

    # ----- bindings

    def _bind(self, at: int, name: str, lo: int, hi: int, definite: bool) -> None:
        if lo < hi:
            self.binds.setdefault((self.scope_of[at], name), []).append(Bind(at, self.depth[at], lo, hi, definite))

    def _collect(self) -> None:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind == PUNCT:
                if tok.value in ("=", ":=", "+=", "||=", "<<") and i:
                    self._assignment(i)
                elif tok.value == "|" and self.lang == "ruby":
                    self._block_params(i)
                elif tok.value == "->" and self.lang in ("java", "kotlin") and self.name(i - 1):
                    self._lambda_param(i)
            elif tok.kind == NAME:
                if tok.value in ("for", "foreach") and self.punct(i + 1, "("):
                    self._for_each(i + 1)
                elif tok.value == "for" and self.lang in ("ruby", "kotlin"):
                    self._for_in(i)
                elif (
                    tok.value in _APPENDS
                    and self.punct(i + 1, "(")
                    and self.punct(i - 1, ".")
                    and self.name(i - 2)
                    and (i < 3 or not self.punct(i - 3, "."))
                ):
                    self._bind(i - 2, toks[i - 2].value, i + 2, self.match[i + 1], False)

    def _assignment(self, op: int) -> None:
        toks = self.toks
        value = toks[op].value
        target = op - 1
        if self.lang == "kotlin" and value == "=":  # val x: Type = ...
            k = op - 1
            while k > max(op - 12, 1) and toks[k].line == toks[op].line:
                if self.punct(k, ":") and self.name(k - 1) and self.name(k - 2) in ("val", "var"):
                    target = k - 1
                    break
                k -= 1
        name = self.name(target)
        if name is None or name in _C_KEYWORDS:
            return
        if target and toks[target - 1].kind == PUNCT and toks[target - 1].value in (".", "?.", "&.", "::", "->"):
            return
        if value == "<<" and (self.lang != "ruby" or not self._first_on_line(target)):
            return
        lo = op + 1
        hi = self.expr_end(lo)
        definite = value in ("=", ":=")
        names = [name]
        k = target - 1
        while value in ("=", ":=") and self.punct(k, ",") and self.name(k - 1):  # a, b := f()
            names.append(self.toks[k - 1].value)
            k -= 2
        for item in names:
            self._bind(target, item, lo, hi, definite)

    def _for_each(self, open_: int) -> None:
        close = self.match[open_]
        if close < 0:
            return
        for k in range(open_ + 1, close):
            tok = self.toks[k]
            if (tok.kind == PUNCT and tok.value == ":") or (tok.kind == NAME and tok.value == "in"):
                if self.name(k - 1):
                    self._bind(k - 1, self.toks[k - 1].value, k + 1, close, True)
                return

    def _for_in(self, i: int) -> None:
        k = i + 1
        names: list[int] = []
        while k < min(self.n, i + 12) and self.name(k) != "in":
            if self.name(k):
                names.append(k)
            k += 1
        if self.name(k) == "in":
            hi = self.expr_end(k + 1)
            for pos in names:
                self._bind(pos, self.toks[pos].value, k + 1, hi, True)

    def _block_params(self, bar: int) -> None:
        """``recv.each do |x|`` and ``recv.map { |x| ... }``: ``x`` takes the receiver's data."""
        opener = bar - 1
        if not (self.name(opener) == "do" or self.punct(opener, "{")):
            return
        k = bar + 1
        names: list[int] = []
        while k < min(self.n, bar + 16) and not self.punct(k, "|"):
            if self.name(k):
                names.append(k)
            k += 1
        method = opener - 1
        if self.punct(method, ")") and self.match[method] > 0:
            method = self.match[method] - 1
        if self.name(method) not in _BLOCK_ITERATORS or not self.punct(method - 1, ".", "&."):
            return
        lo = self._chain_start(method - 2)
        for pos in names:
            self._bind(pos, self.toks[pos].value, lo, method - 1, True)

    def _lambda_param(self, arrow: int) -> None:
        """``list.forEach(x -> ...)``: ``x`` takes the receiver's data."""
        name_pos = arrow - 1
        if not self.punct(name_pos - 1, "("):
            return
        method = name_pos - 2
        if self.name(method) in _BLOCK_ITERATORS and self.punct(method - 1, "."):
            lo = self._chain_start(method - 2)
            self._bind(name_pos, self.toks[name_pos].value, lo, method - 1, True)

    def _chain_start(self, k: int) -> int:
        """Index of the first token of the member chain that ends at token ``k``."""
        for _ in range(64):
            if k <= 0:
                return max(k, 0)
            tok = self.toks[k]
            if tok.kind == PUNCT and tok.value in (")", "]") and self.match[k] > 0:
                k = self.match[k]
                if self.name(k - 1):
                    k -= 1
            if self.punct(k - 1, ".", "?.", "&.", "::") and k >= 2:
                k -= 2
                continue
            return k
        return k

    def effective(self, name: str, pos: int) -> list[Bind]:
        out: list[Bind] = []
        depth = self.depth[pos]
        sid = self.scope_of[pos]
        while True:
            for bind in reversed(self.binds.get((sid, name), ())[-MAX_BINDINGS * 4 :]):
                if bind.pos >= pos or bind.lo <= pos < bind.hi:
                    continue
                out.append(bind)
                self.steps += 1
                if (bind.definite and bind.depth <= depth) or len(out) >= MAX_BINDINGS:
                    return out
            scope = self.scopes[sid]
            if not scope.closure or sid == 0:
                return out
            sid = scope.parent

    def param_kind(self, name: str, pos: int) -> str | None:
        sid = self.scope_of[pos]
        while True:
            scope = self.scopes[sid]
            if name in scope.params:
                return scope.params[name]
            if not scope.closure or sid == 0:
                return None
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
        self.memo[key] = []  # a cycle through bindings reads as clean
        result = self._span(lo, hi, depth)
        self.memo[key] = result
        return result

    def _source(self, label: str, line: int, *, obj: bool = False) -> Origin:
        return Origin(label, line, frozenset(), obj, (TraceStep(line, f"{label} (source)"),))

    def _span(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        while lo < hi and (
            self.punct(lo, "&", "*", "...") or self.name(lo) in ("await", "range", "yield", "out", "ref")
        ):
            lo += 1
        if lo >= hi:
            return []
        first = toks[lo]
        if first.kind == PUNCT and first.value in ("!", "-", "+", "~"):
            return []
        if first.kind == NAME and first.value in ("not", "defined?", "lambda", "proc", "func", "fun", "delegate"):
            return []
        if self.name(lo + 1) is None and self.punct(lo + 1, "->", "=>") and self.lang != "ruby":
            return []  # a lambda
        terms, low, arith = self._top_level(lo, hi)
        if terms is not None:
            origins: list[Origin] = []
            for a, b in terms:
                _add(origins, self.taint(a, b, depth + 1))
            return origins
        if low or arith:
            return []
        return self._primary(lo, hi, depth)

    def _top_level(self, lo: int, hi: int) -> tuple[list[tuple[int, int]] | None, bool, bool]:
        """Operand spans joined by ``+``, a ternary, ``??``, ``?:`` or Ruby ``||``/``%`` (their data is the union), and
        whether a comparison or arithmetic operator occurs at the top level."""
        cuts: list[int] = []
        question = -1
        low = arith = False
        k = lo
        toks = self.toks
        ruby = self.lang == "ruby"
        while k < hi:
            tok = toks[k]
            if tok.kind == PUNCT:
                value = tok.value
                if value in _OPEN and self.match[k] > k:
                    k = self.match[k] + 1
                    continue
                if k > lo and (value in ("+", "??", "?:") or (ruby and value in ("||", "%"))):
                    cuts.append(k)
                elif value == "?" and question < 0 and k > lo:
                    question = k
                elif value == ":" and question >= 0:
                    return [(question + 1, k), (k + 1, hi)], False, False
                elif value in _LOW_OPS or (value == "||" and not ruby) or (ruby and value in ("<", ">")):
                    low = True
                elif value in _ARITH and k > lo:
                    arith = True
            elif tok.kind == NAME and tok.value in _LOW_NAMES and k > lo:
                low = True
            k += 1
        if question >= 0:
            return [(question + 1, hi)], False, False
        if low:
            return None, True, False
        if cuts:
            bounds = [lo - 1, *cuts, hi]
            return [(bounds[j] + 1, bounds[j + 1]) for j in range(len(bounds) - 1)], False, False
        return None, False, arith

    def _primary(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        tok = toks[lo]
        if tok.kind in (STR, NUM):
            return self._postfix([], "clean", lo + 1, hi, depth, path=tok.value)
        if tok.kind in (ISTR, SHELL):
            return self._postfix(self._interpolated(tok, lo), "value", lo + 1, hi, depth, path="")
        if tok.kind == PUNCT and tok.value == "(" and self.match[lo] > lo:
            close = self.match[lo]
            if self._is_cast(lo, close, hi):
                names = [t.value.lower() for t in toks[lo + 1 : close] if t.kind == NAME]
                return [] if names and names[-1] in _NUMERIC_TYPES else self.taint(close + 1, hi, depth + 1)
            inner = self.taint(lo + 1, close, depth + 1)
            return self._postfix(inner, "value" if inner else "clean", close + 1, hi, depth, path="")
        if tok.kind == PUNCT and tok.value == "[" and self.match[lo] > lo:
            close = self.match[lo]
            if close == lo + 1 and self.name(lo + 2) and self.punct(lo + 3, "("):  # Go []byte(x)
                origins = self._union(self.args(lo + 3), depth)
                return self._postfix(origins, "value", self.match[lo + 3] + 1, hi, depth, path="")
            origins = self._union(self.split(lo + 1, close), depth)
            return self._postfix(origins, "value", close + 1, hi, depth, path="")
        if tok.kind == NAME:
            if tok.value == "new":
                return self._new(lo, hi, depth)
            return self._chain(lo, hi, depth)
        return []

    def _is_cast(self, lo: int, close: int, hi: int) -> bool:
        if self.lang not in ("java", "csharp") or close + 1 >= hi:
            return False
        inner = self.toks[lo + 1 : close]
        if not inner or not all(t.kind == NAME or (t.kind == PUNCT and t.value in ".<>[]?,") for t in inner):
            return False
        nxt = self.toks[close + 1]
        return nxt.kind in (NAME, STR, ISTR, NUM) or (nxt.kind == PUNCT and nxt.value == "(")

    def _union(self, spans: list[tuple[int, int]], depth: int) -> list[Origin]:
        origins: list[Origin] = []
        for a, b in spans:
            _add(origins, self.taint(a, b, depth + 1))
        return origins

    def _new(self, lo: int, hi: int, depth: int) -> list[Origin]:
        k = lo + 1
        last = ""
        while k < hi and (self.name(k) or self.punct(k, ".", "<", ">", ",", "?")):
            if self.name(k) and not self.punct(k - 1, "<", ","):
                last = self.toks[k].value
            k += 1
        if not self.punct(k, "(") or self.match[k] < 0:
            return []
        origins = self._union(self.args(k), depth) if last in _PROPAGATE_NEW else []
        return self._postfix(origins, "value" if origins else "clean", self.match[k] + 1, hi, depth, path=last)

    def _interpolated(self, tok: Token, pos: int) -> list[Origin]:
        origins: list[Origin] = []
        for name in tok.vars:
            _add(origins, self._root(name, tok.line, pos, interpolated=True)[0])
        return origins

    def _root(self, name: str, line: int, pos: int, *, interpolated: bool = False) -> tuple[list[Origin], str]:
        """(origins, state) of a bare name: state ``object`` (a request object), ``value`` or ``clean``."""
        kind = self.param_kind(name, pos)
        if kind == "object":
            return ([self._source(name, line)] if interpolated else [self._source(name, line, obj=True)]), "object"
        if kind == "value":
            return [self._source(name, line)], "value"
        bound = self.effective(name, pos)
        if bound:
            origins: list[Origin] = []
            for bind in bound:
                for origin in self.taint(bind.lo, bind.hi, 1):
                    step = TraceStep(self.toks[bind.pos].line, f"assigned to {name}")
                    trace = origin.trace if len(origin.trace) >= MAX_TRACE else (*origin.trace, step)
                    _add(origins, [Origin(origin.label, origin.line, origin.cleared, origin.obj, trace)])
            objects = [o for o in origins if o.obj]
            return origins, "object" if objects and len(objects) == len(origins) else ("value" if origins else "clean")
        if name in _ROOT_VALUES.get(self.lang, ()):
            return [self._source(name, line)], "value"
        if name in _ROOT_OBJECTS.get(self.lang, ()):
            return ([self._source(name, line)] if interpolated else [self._source(name, line, obj=True)]), "object"
        return [], "clean"

    def _chain(self, lo: int, hi: int, depth: int) -> list[Origin]:
        toks = self.toks
        tok = toks[lo]
        name = tok.value
        if self.punct(lo + 1, "(") and self.match[lo + 1] > lo:
            close = self.match[lo + 1]
            if name in _NUMERIC_CALLS:
                return []
            origins = self._union(self.args(lo + 1), depth) if name in _PROPAGATE[self.family] else []
            if self.lang == "go" and name in ("string", "append"):
                origins = self._union(self.args(lo + 1), depth)
            return self._postfix(origins, "value" if origins else "clean", close + 1, hi, depth, path=name)
        if self.lang == "kotlin" and self.punct(lo + 1, "<") and name.startswith("receive"):
            return []
        member = self.toks[lo + 2].value if lo + 2 < hi and self.punct(lo + 1, ".", "?.", "&.") else ""
        if (_ARCHIVE_ENTRY.match(name) and member in _ARCHIVE_MEMBERS) or (
            member in _UPLOAD_MEMBERS and _UPLOAD.search(name)
        ):  # names chosen by whoever made the archive (zip slip) or uploaded the file
            end = lo + 3
            if self.punct(end, "(") and self.match[end] > end:
                end = self.match[end] + 1
            return self._postfix(
                [self._source(f"{name}.{self.toks[lo + 2].value}", tok.line)], "value", end, hi, depth, path=""
            )
        origins, state = self._root(name, tok.line, lo)
        return self._postfix(origins, state, lo + 1, hi, depth, path=name)

    def _postfix(self, origins: list[Origin], state: str, k: int, hi: int, depth: int, *, path: str) -> list[Origin]:
        toks = self.toks
        members_of_request = _REQUEST_MEMBERS[self.lang]
        while k < hi:
            if self.punct(k, "[") and self.match[k] > k:
                if state == "object":
                    origins = [Origin(o.label, o.line, o.cleared, False, o.trace) for o in origins]
                    state = "value"
                k = self.match[k] + 1
                continue
            if self.punct(k, "!!"):
                k += 1
                continue
            if not (self.punct(k, ".", "?.", "&.", "::") and k + 1 < hi and toks[k + 1].kind == NAME):
                break
            member = toks[k + 1].value
            call = self.punct(k + 2, "(") and self.match[k + 2] > k
            generic_call = self.punct(k + 2, "<")
            after = self.match[k + 2] + 1 if call else k + 2
            qualified = f"{path}.{member}" if path else member
            if state == "object":
                if member in _OBJECT_MEMBERS[self.lang]:
                    label = f"{origins[0].label}.{member}" if origins else member
                    origins = [self._source(label, toks[k + 1].line, obj=True)]
                elif member in members_of_request:
                    label = f"{origins[0].label}.{member}" if origins else member
                    origins, state = [self._source(label, toks[k + 1].line)], "value"
                else:
                    return []
            elif state == "value":
                if member in _CLEAN_METHODS:
                    return []
            elif call and qualified in _SOURCE_CALLS:
                origins, state = [self._source(f"{qualified}()", toks[k + 1].line)], "value"
            elif call and (
                member in _PROPAGATE[self.family] or (self.lang == "go" and path in _GO_PROPAGATING_PACKAGES)
            ):
                if member in _NUMERIC_CALLS or member in _CLEAN_METHODS or member in _GO_SANITIZERS:
                    return []
                found = self._union(self.args(k + 2), depth)
                if found:
                    origins, state = found, "value"
            elif generic_call or call:
                origins, state = [], "clean"
            path = qualified if state == "clean" and not call else ""
            k = after
            if generic_call:  # call.receive<T>() in Kotlin
                while k < hi and not self.punct(k, "("):
                    k += 1
                if self.punct(k, "(") and self.match[k] > k:
                    k = self.match[k] + 1
        return [] if state == "object" else origins  # a request object itself is not data
