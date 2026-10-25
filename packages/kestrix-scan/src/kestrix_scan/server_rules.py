# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Go, Java, Kotlin, C# and Ruby rules (``go.*``, ``java.*``, ``cs.*``, ``rb.*``) over the tokenizers and the structural
index in ``server_index.py``. Source is never run.

Each rule matches one precise shape. A request value that reaches a sink inside one function gives a finding with a
trace; SQL sinks also report, at lower severity and confidence, SQL text built by concatenation, interpolation or a
format call from a value that is not a literal (``_built``). Rules without a source (``go.tls.insecure_skip_verify``,
``java.deserialize.unsafe``, ``java.xxe.parser``, ``cs.deserialize.unsafe``) match the configuration or the API
itself. ERB templates (``*.erb``) are checked for ``<%== %>``, ``raw`` and ``html_safe`` of a value that is not a
literal. Kotlin files share the Java rules.

Minified files are skipped as ``minified``; files over the tokenizer's bounds, or past the work bound, as
``too_complex``.
"""

from __future__ import annotations

import re

from . import c_tokens, ruby_tokens
from .models import Confidence, Severity, SkipReason, TraceStep, clip_snippet
from .php_index import Origin, TooComplex, best
from .php_tokens import ISTR, NAME, NUM, PUNCT, SHELL, STR, Token
from .python_rules import _SQL
from .registry import Hit
from .server_index import Index

SERVER_SUFFIXES: dict[str, str] = {
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".rb": "ruby",
    ".erb": "erb",
}
MAX_AVERAGE_LINE = 500
DATA = "data"  # the one sink class: sanitizers make a value clean for every sink, so no class is cleared alone

# The untainted "built" SQL finding counts a part that is not a literal only under this strict reading: a local
# variable assigned in the function (followed to its value when the SQL argument is a lone name), a call result or a
# member; parameters, constants and names that read as a table, column or sort key do not count.
_BUILT_FOLLOW = True
_BUILT_PARAMS = False
_IDENTIFIER_NAME = re.compile(
    r"(?i)table|tbl|prefix|column|field|schema|database|^(?:db|col|cols|order|sort|dir|limit|offset)(?:_|$)|"
    r"(?:Table|Column|Order|Sort|Limit|Offset|Prefix|Schema)$"
)
_CONSTANT = re.compile(r"^[A-Z][A-Z0-9_]+$")

# ----- sink tables

_GO_SQL = frozenset(
    {"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext", "Prepare", "PrepareContext"}
    | {"Queryx", "QueryRowx", "MustExec", "NamedExec", "NamedQuery", "Raw"}
)
_GO_SQL_FRAGMENTS = frozenset({"Where", "Order", "Having", "Joins", "Group", "Or", "Not"})
_GO_TEMPLATE_TYPES = frozenset({"HTML", "JS", "HTMLAttr", "URL", "CSS", "JSStr", "Srcset"})
_GO_FILE_CALLS: dict[str, tuple[int, ...]] = {
    "os.Open": (0,),
    "os.OpenFile": (0,),
    "os.ReadFile": (0,),
    "os.Create": (0,),
    "os.WriteFile": (0,),
    "os.Remove": (0,),
    "os.RemoveAll": (0,),
    "os.Mkdir": (0,),
    "os.MkdirAll": (0,),
    "os.Rename": (0, 1),
    "os.ReadDir": (0,),
    "os.Chmod": (0,),
    "ioutil.ReadFile": (0,),
    "ioutil.WriteFile": (0,),
    "ioutil.ReadDir": (0,),
    "http.ServeFile": (2,),
    "os.DirFS": (0,),
}
_GO_URL_CALLS: dict[str, int] = {
    "http.Get": 0,
    "http.Head": 0,
    "http.Post": 0,
    "http.PostForm": 0,
    "http.NewRequest": 1,
    "http.NewRequestWithContext": 2,
    "net.Dial": 1,
    "net.DialTimeout": 1,
}
_JAVA_SQL = frozenset(
    {"executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "addBatch", "prepareStatement", "prepareCall"}
    | {"nativeSQL", "createQuery", "createNativeQuery", "createSQLQuery", "queryForObject", "queryForList"}
    | {"queryForMap", "queryForRowSet", "query", "update", "batchUpdate", "execSQL", "rawQuery", "queryForLong"}
)
_JAVA_DESER_NEW = frozenset({"ObjectInputStream", "XMLDecoder"})
_JAVA_DESER_SAFE = re.compile(r"\bresolveClass\b|ObjectInputFilter|setObjectInputFilter|ValidatingObjectInputStream")
_XSTREAM_SAFE = re.compile(r"\ballowTypes\w*\s*\(|\baddPermission\s*\(|\bsetupDefaultSecurity\s*\(")
_YAML_SAFE = re.compile(r"\bSafeConstructor\b|\bLoaderOptions\b")
_JAVA_XML_FACTORIES = frozenset(
    {"DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory", "SchemaFactory"}
    | {"XMLReaderFactory", "SAXTransformerFactory"}
)
_JAVA_XML_NEW = frozenset({"SAXReader", "SAXBuilder"})
_XML_HARDENED = re.compile(
    r"disallow-doctype-decl|external-general-entities|external-parameter-entities|load-external-dtd"
    r"|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|ACCESS_EXTERNAL_STYLESHEET"
    r"|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|setExpandEntityReferences\s*\(\s*false|XMLConstants\."
    r"|setEntityResolver\s*\(|XmlUtils?\.\w*(?:Secure|Safe)\w*\s*\("
)
_JAVA_FILE_NEW = frozenset(
    {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile", "PrintWriter"}
)
_JAVA_FILE_STATIC = re.compile(
    r"^(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readAllLines|readString|lines|newInputStream|newOutputStream"
    r"|newBufferedReader|newBufferedWriter|write|writeString|copy|move|delete|deleteIfExists|createFile"
    r"|createDirectories|createDirectory|list|walk|newDirectoryStream))$"
)
_JAVA_URL_NEW = frozenset({"URL", "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpHead", "HttpPatch"})
_JAVA_URL_METHODS = frozenset(
    {"getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "connect", "openConnection"}
)
_JAVA_WRITES = frozenset({"write", "print", "println", "append", "printf", "format", "respondText"})
_CS_SQL_NEW = frozenset(
    {"SqlCommand", "SqlDataAdapter", "OleDbCommand", "OleDbDataAdapter", "OdbcCommand", "MySqlCommand"}
    | {"NpgsqlCommand", "SQLiteCommand", "SqliteCommand", "OracleCommand", "MySqlDataAdapter", "NpgsqlDataAdapter"}
)
_CS_SQL_METHODS = frozenset(
    {"ExecuteSqlRaw", "ExecuteSqlRawAsync", "FromSqlRaw", "ExecuteSqlCommand", "ExecuteSqlCommandAsync", "SqlQuery"}
    | {"SqlQueryRaw", "Query", "QueryAsync", "Execute", "ExecuteAsync", "QueryFirst", "QueryFirstOrDefault"}
    | {"QueryFirstAsync", "QueryFirstOrDefaultAsync", "QuerySingle", "QuerySingleOrDefault", "QueryMultiple"}
    | {"ExecuteScalar", "ExecuteScalarAsync", "ExecuteReader", "ExecuteReaderAsync", "QueryMultipleAsync"}
)
_CS_DESER_NEW = frozenset(
    {"BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter", "ObjectStateFormatter"}
)
_CS_FILE = re.compile(
    r"^(?:File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenText|Open|OpenWrite|Create"
    r"|CreateText|Delete|WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|Copy|Move|Replace|ReadAllTextAsync"
    r"|ReadAllBytesAsync|WriteAllTextAsync|WriteAllBytesAsync)|Directory\.(?:Delete|CreateDirectory|GetFiles"
    r"|EnumerateFiles|GetDirectories|Move)|PhysicalFile|ExtractToFile)$"
)
_CS_FILE_NEW = frozenset({"FileStream", "StreamReader", "StreamWriter", "FileInfo", "DirectoryInfo"})
_CS_URL = re.compile(
    r"^(?:WebRequest\.Create|HttpWebRequest\.Create|GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync"
    r"|PostAsync|PutAsync|DeleteAsync|SendAsync|DownloadString|DownloadData|DownloadFile|OpenRead|UploadString)$"
)
_RB_SQL = frozenset(
    {"find_by_sql", "where", "order", "reorder", "pluck", "select", "joins", "group", "having", "from", "exists?"}
    | {"execute", "exec_query", "select_all", "select_one", "select_value", "select_values", "select_rows", "lock"}
    | {"count_by_sql", "delete_all", "update_all", "find_by", "calculate", "not", "rewhere", "exec_update"}
    | {"exec_delete", "exec_insert", "sanitize_sql_array"}
)
_RB_SQL_RAW = frozenset({"where", "order", "reorder", "pluck", "group", "having", "joins", "not", "rewhere", "lock"})
_RB_EXEC = frozenset({"system", "exec", "spawn", "popen", "capture2", "capture2e", "capture3", "popen2", "popen3"})
_RB_FILE = frozenset(
    {"File.read", "File.open", "File.new", "File.write", "File.delete", "File.unlink", "File.readlines", "File.binread"}
    | {
        "File.foreach",
        "File.rename",
        "IO.read",
        "IO.readlines",
        "IO.binread",
        "Dir.glob",
        "Dir.entries",
        "FileUtils.rm",
    }
    | {"FileUtils.rm_rf", "FileUtils.rm_r", "FileUtils.mv", "FileUtils.cp", "FileUtils.mkdir_p", "send_file"}
    | {"Pathname.new", "File.expand_path", "Dir.children", "File.copy_stream", "FileUtils.cp_r", "File.symlink"}
)
_ERB_TAG = re.compile(r"<%(==|=)(.*?)-?%>", re.DOTALL)
_ERB_RAW = re.compile(r"^\s*raw\b\s*\(?|\.html_safe\b")
_ERB_SAFE = re.compile(r"^\s*(?:raw\s*\(?\s*)?(?:['\"][^'\"#]*['\"]|\d+|t\(|I18n\.t\(|render\b|yield\b|content_for\b)")
_ERB_REQUEST = re.compile(r"\bparams\b|\brequest\.|\bcookies\[")


def minified(text: str) -> bool:
    return len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE


def server_language(rel: str) -> str | None:
    """The language of a path by its suffix (``erb`` for ERB templates), or None."""
    lowered = rel.lower()
    dot = lowered.rfind(".")
    return SERVER_SUFFIXES.get(lowered[dot:]) if dot >= 0 else None


def check_server(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one Go, Java, Kotlin, C#, Ruby or ERB file, or the reason it was not analyzed."""
    language = server_language(rel)
    if language is None:
        return []
    if minified(text):
        return "minified"
    lines = text.splitlines()
    if language == "erb":
        return _erb(text, lines)
    tokens = ruby_tokens.tokenize(text) if language == "ruby" else c_tokens.tokenize(text, language)
    if tokens is None:
        return "too_complex"
    if not tokens:
        return []
    try:
        return _unique(_Checker(Index(tokens, lines, language), text, lines).run())
    except (TooComplex, RecursionError):
        return "too_complex"


def _unique(hits: list[Hit]) -> list[Hit]:
    seen: set[tuple[str, int]] = set()
    out: list[Hit] = []
    for item in hits:
        key = (item.rule_id, item.line)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _erb(text: str, lines: list[str]) -> list[Hit]:
    hits: list[Hit] = []
    for match in _ERB_TAG.finditer(text):
        marker, expr = match.group(1), match.group(2)
        if marker != "==" and not _ERB_RAW.search(expr):
            continue
        if _ERB_SAFE.match(expr) and not _ERB_REQUEST.search(expr):
            continue
        line = text.count("\n", 0, match.start()) + 1
        tainted = bool(_ERB_REQUEST.search(expr))
        source = lines[line - 1] if 0 < line <= len(lines) else ""
        how = "<%== %>" if marker == "==" else ("raw" if "raw" in expr.split(".")[0] else "html_safe")
        hits.append(
            Hit(
                "rb.xss.html_safe",
                line,
                match.start() - text.rfind("\n", 0, match.start()),
                line + match.group(0).count("\n"),
                f"The template prints this value with {how}, without escaping,"
                + (" and it comes from the request." if tainted else " and it is not a literal."),
                clip_snippet(source),
                severity=None if tainted else "low",
                confidence="high" if tainted else "low",
            )
        )
    return hits


class _Checker:
    def __init__(self, index: Index, text: str, lines: list[str]) -> None:
        self.ix = index
        self.toks = index.toks
        self.text = text
        self.lines = lines
        self.lang = index.lang
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
        origin: Origin | None = None,
        sink: str = "",
    ) -> None:
        tok = self.toks[at]
        text = self.lines[tok.line - 1] if 0 < tok.line <= len(self.lines) else ""
        trace: tuple[TraceStep, ...] = ()
        if origin is not None:
            trace = (*origin.trace, TraceStep(tok.line, f"reaches {sink}"))
            message = f"{message} The value comes from {origin.label} (line {origin.line})."
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
                trace=trace,
            )
        )

    def flow(self, rule_id: str, at: int, spans: list[tuple[int, int]], sink: str, message: str) -> bool:
        for lo, hi in spans:
            origin = best(self.ix.taint(lo, hi), DATA)
            if origin is not None:
                self.hit(rule_id, at, message, origin=origin, sink=sink)
                return True
        return False

    # ----- shape helpers

    def chain(self, i: int) -> list[str]:
        """Names of the member chain that ends at the name at ``i`` (calls and subscripts skipped):
        ``Runtime.getRuntime().exec`` gives ``['Runtime', 'getRuntime', 'exec']``."""
        out = [self.toks[i].value]
        k = i - 1
        for _ in range(16):
            if not self.ix.punct(k, ".", "?.", "&.", "::") or k < 1:
                break
            k -= 1
            if self.ix.punct(k, ")", "]") and self.ix.match[k] > 0:
                k = self.ix.match[k] - 1
            name = self.ix.name(k)
            if name is None:
                break
            out.insert(0, name)
            k -= 1
        return out

    def call_args(self, i: int) -> tuple[list[tuple[int, int]], int] | None:
        """(argument spans, index of the last token) of the call at the name ``i``: ``f(a, b)``, or for Ruby also
        ``f a, b`` without parentheses on the same line. None when ``i`` is not called."""
        ix = self.ix
        if ix.punct(i + 1, "(") and ix.match[i + 1] > i:
            return ix.args(i + 1), ix.match[i + 1]
        if self.lang == "ruby" and i + 1 < ix.n:
            nxt = self.toks[i + 1]
            if nxt.line == self.toks[i].end_line and (
                nxt.kind in (NAME, STR, ISTR, SHELL, NUM) or (nxt.kind == PUNCT and nxt.value in ("[", ":", "@"))
            ):
                if nxt.kind == NAME and nxt.value in ("if", "unless", "do", "and", "or", "then", "end"):
                    return None
                end = self._ruby_args_end(i + 1)
                return ix.split(i + 1, end), end - 1
        return None

    def _ruby_args_end(self, lo: int) -> int:
        k = lo
        ix = self.ix
        while k < ix.n:
            tok = self.toks[k]
            if k > lo and tok.line > self.toks[k - 1].end_line and not ix.punct(k - 1, ",", "+", "\\"):
                return k
            if tok.kind == PUNCT and tok.value in ("(", "[", "{") and ix.match[k] > k:
                if tok.value == "{" and k > lo:
                    return k
                k = ix.match[k] + 1
                continue
            if tok.kind == PUNCT and tok.value in (";", ")", "]", "}"):
                return k
            if (
                tok.kind == NAME
                and tok.value in ("if", "unless", "do", "and", "or", "then", "rescue", "while")
                and k > lo
            ):
                return k
            k += 1
        return ix.n

    def literal(self, lo: int, hi: int) -> bool:
        return hi == lo + 1 and self.toks[lo].kind in (STR, NUM)

    # ----- walk

    def run(self) -> list[Hit]:
        toks = self.toks
        for i, tok in enumerate(toks):
            if tok.kind == NAME:
                prev = toks[i - 1] if i else None
                if self._declared(i, prev):
                    continue
                _HANDLERS[self.lang](self, i, tok, prev)
            elif tok.kind == SHELL and self.lang == "ruby":
                origin = best(self.ix._interpolated(tok, i), DATA)
                if origin is not None:
                    self.hit(
                        "rb.exec.command",
                        i,
                        "A backtick command is built from request data.",
                        origin=origin,
                        sink="backticks",
                    )
        return self.hits

    def _declared(self, i: int, prev: Token | None) -> bool:
        """Is the name at ``i`` the name of a function being declared (``func f(``, ``def f``, ``void f(...) {``)?"""
        if prev is not None and prev.kind == NAME and prev.value in ("func", "fun", "def"):
            return True
        ix = self.ix
        if self.lang in ("java", "csharp") and ix.punct(i + 1, "(") and ix.match[i + 1] > i:
            return (
                prev is not None
                and prev.kind == NAME
                and prev.value != "new"
                and ix._body_after(ix.match[i + 1]) is not None
            )
        return False

    # ----- SQL (every language)

    def sql_arg(self, i: int, sink: str, rule: str, span: tuple[int, int], *, keyword: bool, raw: bool = False) -> bool:
        """Report SQL built from request data, or text built from a value that is not a literal (strict reading).

        ``keyword``: only text that reads as SQL counts for the untainted finding. ``raw``: a fragment such as
        ``where("id = #{id}")``, which has no SQL keyword to look for."""
        lo, hi = span
        dynamic, text = self._built(lo, hi, top=True)
        origin = best(self.ix.taint(lo, hi), DATA)
        if origin is not None and (raw or not keyword or _SQL.search(text) or not text.strip()):
            self.hit(rule, i, f"{sink} runs SQL built from request data.", origin=origin, sink=sink)
            return True
        if dynamic and (raw or _SQL.search(text)):
            self.hit(
                rule,
                i,
                f"{sink} runs SQL text built by concatenation, interpolation or formatting from a value that is not a literal.",
                severity="medium",
                confidence="low",
            )
            return True
        return False

    def _dynamic_name(self, name: str, pos: int, depth: int) -> bool:
        """Is the name at ``pos`` a part that counts as not literal under the strict reading?"""
        if (
            _IDENTIFIER_NAME.search(name)
            or _CONSTANT.match(name)
            or name in ("this", "self", "nil", "null", "true", "false")
        ):
            return False
        binds = self.ix.effective(name, pos)
        if not binds:
            return _BUILT_PARAMS and self.ix.param_kind(name, pos) is None and name[:1].islower()
        return any(not self._literal_value(b.lo, b.hi, depth + 1) for b in binds)

    def _literal_value(self, lo: int, hi: int, depth: int) -> bool:
        """Is the expression a literal, or text built only from literals?"""
        if depth > 4:
            return False
        if hi == lo + 1:
            tok = self.toks[lo]
            if tok.kind in (STR, NUM):
                return True
            if tok.kind == NAME and _CONSTANT.match(tok.value):
                return True
        terms = self.ix.split(lo, hi, "+")
        return len(terms) > 1 and all(self._literal_value(a, b, depth + 1) for a, b in terms)

    def _built(self, lo: int, hi: int, depth: int = 0, *, top: bool = False) -> tuple[bool, str]:
        """(built from a part that is not a literal, the literal text it is built from)."""
        ix = self.ix
        if lo >= hi or depth > 4:
            return False, ""
        terms = ix.split(lo, hi, "+")
        if len(terms) > 1:
            dynamic = False
            texts: list[str] = []
            for a, b in terms:
                tok = self.toks[a]
                if b == a + 1 and tok.kind in (STR, NUM):
                    texts.append(tok.value)
                    continue
                d, t = self._built(a, b, depth + 1)
                part = d or self._part_dynamic(a, b, depth)
                dynamic = dynamic or part
                texts.append(t)
            return dynamic, " ? ".join(texts)
        tok = self.toks[lo]
        if tok.kind in (STR, NUM):
            return False, tok.value
        if tok.kind == ISTR:
            return any(self._dynamic_name(name, lo, depth) for name in tok.vars) or self._has_call(tok), tok.value
        if tok.kind == NAME and hi == lo + 1 and top and _BUILT_FOLLOW:
            binds = ix.effective(tok.value, lo)
            dynamic = False
            texts = []
            for bind in reversed(binds):
                d, t = self._built(bind.lo, bind.hi, depth + 1)
                dynamic = dynamic or d
                texts.append(t)
            return dynamic, " ".join(texts)
        format_call = self._format_call(lo, hi)
        if format_call is not None:
            spans = format_call
            if spans:
                d, t = self._built(*spans[0], depth + 1)
                rest = any(self._part_dynamic(a, b, depth) for a, b in spans[1:])
                return d or rest, t
        return False, ""

    def _has_call(self, tok: Token) -> bool:
        """Does an interpolation of the string call a method (``#{user.name}``, ``{GetId()}``)?"""
        return bool(re.search(r"(?:#\{|\$\{|\{)[^}]*[\w)]\s*(?:\.|\()", tok.value)) and not tok.vars

    def _format_call(self, lo: int, hi: int) -> list[tuple[int, int]] | None:
        """Arguments of a format call that spans ``lo..hi`` (``fmt.Sprintf``, ``String.format``, ``string.Format``,
        Ruby ``format``/``%``), or None."""
        ix = self.ix
        k = hi - 1
        if not ix.punct(k, ")") or ix.match[k] < lo:
            return None
        name_at = ix.match[k] - 1
        name = ix.name(name_at)
        if name not in ("Sprintf", "format", "Format", "sprintf", "formatted"):
            return None
        args = ix.args(ix.match[k])
        if name == "formatted" and ix.punct(name_at - 1, "."):
            return [(lo, name_at - 1), *args]
        return args

    def _part_dynamic(self, a: int, b: int, depth: int) -> bool:
        tok = self.toks[a]
        if b == a + 1:
            if tok.kind in (STR, NUM):
                return False
            if tok.kind == NAME:
                return self._dynamic_name(tok.value, a, depth)
            if tok.kind == ISTR:
                return any(self._dynamic_name(n, a, depth) for n in tok.vars)
            return False
        if (
            tok.kind == NAME
            and self.ix.punct(a + 1, "(")
            and tok.value in ("String", "strconv", "Integer", "int", "len")
        ):
            return False
        if tok.kind == NAME and (_IDENTIFIER_NAME.search(tok.value) or _CONSTANT.match(tok.value)):
            return False
        last = self.toks[b - 1]
        if last.kind == NAME and _IDENTIFIER_NAME.search(last.value):
            return False
        return not (tok.kind == PUNCT and tok.value == "(" and b - a == 3)  # a cast such as (int) x


# ----- Go


def _go(c: _Checker, i: int, tok: Token, prev: Token | None) -> None:
    ix = c.ix
    word = tok.value
    if word == "InsecureSkipVerify" and ix.punct(i + 1, ":", "=") and ix.name(i + 2) == "true":
        c.hit(
            "go.tls.insecure_skip_verify",
            i,
            "InsecureSkipVerify: true turns off certificate and host name checks, so anyone on the network path can impersonate the server.",
        )
        return
    if not ix.punct(i + 1, "(") or ix.match[i + 1] < 0:
        return
    names = c.chain(i)
    qualified = ".".join(names[-2:])
    args = ix.args(i + 1)
    if qualified in ("exec.Command", "exec.CommandContext", "syscall.Exec", "os.StartProcess"):
        spans = args[1:] if word == "CommandContext" else args
        c.flow(
            "go.exec.command",
            i,
            spans,
            f"{qualified}()",
            f"{qualified}() runs a program or arguments chosen by request data.",
        )
    elif len(names) >= 2 and (word in _GO_SQL or word in _GO_SQL_FRAGMENTS) and args:
        if names[-2] in ("exec", "template", "tmpl", "t", "tpl", "cmd", "strings", "regexp", "re", "filepath", "url"):
            return
        span = args[1] if word.endswith("Context") and len(args) > 1 else args[0]
        c.sql_arg(i, f".{word}()", "go.sql.injection", span, keyword=word in _GO_SQL, raw=word in _GO_SQL_FRAGMENTS)
    elif len(names) >= 2 and names[-2] == "template" and word in _GO_TEMPLATE_TYPES and len(args) == 1:
        lo, hi = args[0]
        if c.flow(
            "go.xss.unescaped",
            i,
            args,
            f"template.{word}()",
            f"template.{word}() marks request data as safe, so html/template does not escape it.",
        ):
            return
        if not c.literal(lo, hi) and not c._literal_value(lo, hi, 0):
            c.hit(
                "go.xss.unescaped",
                i,
                f"template.{word}() marks a value that is not a literal as safe, so html/template does not escape it.",
                severity="low",
                confidence="low",
            )
    elif qualified in ("fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln", "io.WriteString") and len(args) >= 2:
        if _is_writer(c, args[0]):
            c.flow(
                "go.xss.unescaped",
                i,
                args[1:],
                f"{qualified}()",
                f"{qualified}() writes request data into the HTTP response without escaping it.",
            )
    elif word == "Write" and len(names) == 2 and _is_writer(c, (i - 2, i - 1)) and args:
        c.flow(
            "go.xss.unescaped",
            i,
            args,
            "ResponseWriter.Write()",
            "The handler writes request data into the HTTP response without escaping it.",
        )
    elif qualified in _GO_FILE_CALLS:
        spans = [args[k] for k in _GO_FILE_CALLS[qualified] if k < len(args)]
        c.flow("go.path.traversal", i, spans, f"{qualified}()", f"{qualified}() uses a path built from request data.")
    elif qualified in _GO_URL_CALLS:
        k = _GO_URL_CALLS[qualified]
        if k < len(args):
            c.flow(
                "go.ssrf.request",
                i,
                [args[k]],
                f"{qualified}()",
                f"{qualified}() connects to an address that the request controls.",
            )


def _is_writer(c: _Checker, span: tuple[int, int]) -> bool:
    lo, hi = span
    return hi == lo + 1 and c.toks[lo].kind == NAME and c.ix.param_kind(c.toks[lo].value, lo) == "writer"


# ----- Java and Kotlin


def _java(c: _Checker, i: int, tok: Token, prev: Token | None) -> None:
    ix = c.ix
    word = tok.value
    created = prev is not None and prev.kind == NAME and prev.value == "new"
    if c.lang == "kotlin" and not created and word[:1].isupper() and ix.punct(i + 1, "(") and not ix.punct(i - 1, "."):
        created = True  # Kotlin constructs without `new`
    if not ix.punct(i + 1, "(") or ix.match[i + 1] < 0:
        if (
            word in ("JsonTypeInfo",)
            and ix.punct(i + 1, ".")
            and ix.name(i + 2) == "Id"
            and ix.name(i + 4) in ("CLASS", "MINIMAL_CLASS")
        ):
            c.hit(
                "java.deserialize.unsafe",
                i,
                f"JsonTypeInfo.Id.{ix.name(i + 4)} lets the JSON name any class on the class path to instantiate (Jackson polymorphic typing).",
            )
        return
    args = ix.args(i + 1)
    names = c.chain(i)
    qualified = ".".join(names[-2:])
    if created:
        if word in _JAVA_DESER_NEW and not _JAVA_DESER_SAFE.search(c.text):
            c.hit(
                "java.deserialize.unsafe",
                i,
                f"new {word}() reads objects of any class the stream names, with no class filter.",
            )
        elif word in _JAVA_XML_NEW and not _XML_HARDENED.search(c.text):
            c.hit(
                "java.xxe.parser",
                i,
                f"new {word}() parses XML with DOCTYPEs and external entities allowed; no secure feature is set in this file.",
            )
        elif word == "Yaml" and not args and not _YAML_SAFE.search(c.text):
            c.hit(
                "java.deserialize.unsafe",
                i,
                "new Yaml() without a SafeConstructor builds any class a YAML tag names (SnakeYAML before 2.0).",
            )
        elif word == "ProcessBuilder":
            c.flow(
                "java.exec.command",
                i,
                args,
                "new ProcessBuilder()",
                "ProcessBuilder runs a program or arguments chosen by request data.",
            )
        elif word in _JAVA_FILE_NEW:
            c.flow(
                "java.path.traversal",
                i,
                args[:2],
                f"new {word}()",
                f"new {word}() opens a path built from request data.",
            )
        elif word in _JAVA_URL_NEW and args:
            c.flow(
                "java.ssrf.request",
                i,
                args[:1],
                f"new {word}()",
                f"new {word}() points at a URL that the request controls.",
            )
        return
    if word == "exec" and "getRuntime" in names:
        c.flow("java.exec.command", i, args, "Runtime.exec()", "Runtime.exec() runs a command built from request data.")
    elif word in _JAVA_SQL and len(names) >= 2 and args:
        c.sql_arg(i, f".{word}()", "java.sql.injection", args[0], keyword=True)
    elif (
        word in ("newInstance", "newFactory", "newDefaultFactory", "createXMLReader")
        and len(names) >= 2
        and names[-2] in _JAVA_XML_FACTORIES
    ):
        if not _XML_HARDENED.search(c.text):
            c.hit(
                "java.xxe.parser",
                i,
                f"{qualified}() makes an XML parser with DOCTYPEs and external entities allowed; no secure feature is set in this file.",
            )
    elif word in ("enableDefaultTyping", "activateDefaultTyping", "enableDefaultTypingAsProperty"):
        c.hit(
            "java.deserialize.unsafe",
            i,
            f"{word}() lets the JSON name the class to instantiate (Jackson polymorphic typing).",
        )
    elif word == "fromXML" and not _XSTREAM_SAFE.search(c.text):
        c.hit(
            "java.deserialize.unsafe",
            i,
            "XStream.fromXML() builds any class the XML names; no type permission is set in this file.",
        )
    elif _JAVA_FILE_STATIC.match(qualified):
        c.flow("java.path.traversal", i, args, f"{qualified}()", f"{qualified}() uses a path built from request data.")
    elif (
        word in _JAVA_URL_METHODS
        or qualified in ("URI.create", "Jsoup.connect", "HttpRequest.newBuilder")
        or (word == "url" and "Builder" in names)
    ):
        if args:
            c.flow(
                "java.ssrf.request",
                i,
                args[:1],
                f"{qualified}()",
                f"{qualified}() requests a URL that the request controls.",
            )
    elif word in _JAVA_WRITES and (
        "getWriter" in names or "getOutputStream" in names or names[0] == "out" or word == "respondText"
    ):
        if word == "respondText" and not any(
            "Html" in t.value for t in c.toks[i + 1 : ix.match[i + 1]] if t.kind == NAME
        ):
            return
        c.flow(
            "java.xss.response",
            i,
            args,
            f"{qualified}()",
            "The response writer prints request data into the page without escaping it.",
        )


# ----- C#


def _csharp(c: _Checker, i: int, tok: Token, prev: Token | None) -> None:
    ix = c.ix
    word = tok.value
    created = prev is not None and prev.kind == NAME and prev.value == "new"
    if word in ("CommandText", "FileName", "Arguments") and ix.punct(i + 1, "=") and ix.punct(i - 1, "."):
        lo = i + 2
        span = (lo, ix.expr_end(lo))
        if word == "CommandText":
            c.sql_arg(i, ".CommandText", "cs.sql.injection", span, keyword=True)
        else:
            c.flow(
                "cs.exec.process",
                i,
                [span],
                f"ProcessStartInfo.{word}",
                f"ProcessStartInfo.{word} is set from request data.",
            )
        return
    if word == "TypeNameHandling" and ix.punct(i + 1, ".") and ix.name(i + 2) in ("All", "Auto", "Objects", "Arrays"):
        if not re.search(r"SerializationBinder\s*=", c.text):
            c.hit(
                "cs.deserialize.unsafe",
                i,
                f"TypeNameHandling.{ix.name(i + 2)} lets the JSON name the .NET type to create; no SerializationBinder is set in this file.",
            )
        return
    if not ix.punct(i + 1, "(") or ix.match[i + 1] < 0:
        return
    args = ix.args(i + 1)
    names = c.chain(i)
    qualified = ".".join(names[-2:])
    if created:
        if word in _CS_DESER_NEW:
            c.hit(
                "cs.deserialize.unsafe",
                i,
                f"{word} deserializes any type the payload names; Microsoft says it cannot be made safe.",
            )
        elif word == "JavaScriptSerializer" and any(
            t.value == "SimpleTypeResolver" for t in c.toks[i + 1 : ix.match[i + 1]]
        ):
            c.hit(
                "cs.deserialize.unsafe",
                i,
                "JavaScriptSerializer with a SimpleTypeResolver creates any type the JSON names.",
            )
        elif word in _CS_SQL_NEW and args:
            c.sql_arg(i, f"new {word}()", "cs.sql.injection", args[0], keyword=True)
        elif word == "ProcessStartInfo":
            c.flow(
                "cs.exec.process",
                i,
                args,
                "new ProcessStartInfo()",
                "ProcessStartInfo runs a program or arguments chosen by request data.",
            )
        elif word in _CS_FILE_NEW and args:
            c.flow(
                "cs.path.traversal", i, args[:1], f"new {word}()", f"new {word}() opens a path built from request data."
            )
        return
    if qualified == "Process.Start":
        c.flow(
            "cs.exec.process",
            i,
            args,
            "Process.Start()",
            "Process.Start() runs a program or arguments chosen by request data.",
        )
    elif word in _CS_SQL_METHODS and len(names) >= 2 and args:
        span = (
            args[1]
            if word.startswith(("Query", "Execute")) and len(args) > 1 and _is_connection_arg(c, args[0])
            else args[0]
        )
        c.sql_arg(
            i,
            f".{word}()",
            "cs.sql.injection",
            span,
            keyword=word not in ("ExecuteSqlRaw", "ExecuteSqlRawAsync", "FromSqlRaw"),
        )
    elif _CS_FILE.match(qualified) or _CS_FILE.match(word):
        spans = args[:2] if word in ("Copy", "Move", "Replace") else args[:1]
        c.flow("cs.path.traversal", i, spans, f"{qualified}()", f"{qualified}() uses a path built from request data.")
    elif _CS_URL.match(qualified) or (_CS_URL.match(word) and len(names) >= 2):
        c.flow(
            "cs.ssrf.request", i, args[:1], f"{qualified}()", f"{qualified}() requests a URL that the request controls."
        )


def _is_connection_arg(c: _Checker, span: tuple[int, int]) -> bool:
    lo, hi = span
    return hi == lo + 1 and c.toks[lo].kind == NAME and "conn" in c.toks[lo].value.lower()


# ----- Ruby


def _ruby(c: _Checker, i: int, tok: Token, prev: Token | None) -> None:
    ix = c.ix
    word = tok.value
    member = prev is not None and prev.kind == PUNCT and prev.value in (".", "&.")
    if word in ("html_safe", "constantize", "safe_constantize") and member:
        lo = ix._chain_start(i - 2)
        if word == "html_safe":
            if c.flow(
                "rb.xss.html_safe",
                i,
                [(lo, i - 1)],
                ".html_safe",
                "html_safe marks request data as safe HTML, so Rails does not escape it.",
            ):
                return
            if not c.literal(lo, i - 1) and not c._literal_value(lo, i - 1, 0) and c.toks[lo].kind != STR:
                c.hit(
                    "rb.xss.html_safe",
                    i,
                    "html_safe marks a value that is not a literal as safe HTML, so Rails does not escape it.",
                    severity="low",
                    confidence="low",
                )
        else:
            c.flow(
                "rb.reflection.constantize",
                i,
                [(lo, i - 1)],
                f".{word}",
                f"{word} turns request data into a class, so the request picks which class the code uses.",
            )
        return
    found = c.call_args(i)
    if found is None:
        return
    args, _ = found
    if not args:
        return
    names = c.chain(i)
    qualified = ".".join(names[-2:])
    if word == "raw" and not member:
        if not c.flow(
            "rb.xss.html_safe", i, args[:1], "raw()", "raw() prints request data without escaping it."
        ) and not c.literal(*args[0]):
            c.hit(
                "rb.xss.html_safe",
                i,
                "raw() prints a value that is not a literal without escaping it.",
                severity="low",
                confidence="low",
            )
    elif (
        (word in ("send", "public_send", "__send__", "try")
        and member)
        or (word in ("send", "public_send") and not member)
    ):
        c.flow("rb.reflection.send", i, args[:1], f"{word}()", f"{word}() calls the method that request data names.")
    elif word == "const_get":
        c.flow(
            "rb.reflection.constantize",
            i,
            args[:1],
            "const_get()",
            "const_get() looks up the class that request data names.",
        )
    elif word in _RB_EXEC and (not member or names[0] in ("Kernel", "IO", "Open3", "PTY")):
        if len(args) == 1 or c.ix.taint(*args[0]):
            c.flow(
                "rb.exec.command",
                i,
                args[:1],
                f"{qualified}()",
                f"{qualified}() runs a shell command built from request data.",
            )
    elif word in _RB_SQL and (member or word in ("find_by_sql",)):
        first = args[0]
        if c.ix.name(first[0]) and c.ix.punct(first[0] + 1, ":"):
            return  # where(name: value): a hash condition, quoted by Rails
        if len(args) > 1 and word in ("where", "find_by", "not", "rewhere", "exists?") and c.toks[first[0]].kind == STR:
            return  # where("a = ?", value): bound parameters
        c.sql_arg(
            i,
            f".{word}()" if member else f"{word}()",
            "rb.sql.injection",
            first,
            keyword=word not in _RB_SQL_RAW,
            raw=word in _RB_SQL_RAW,
        )
    elif qualified in _RB_FILE or (word == "send_file" and not member):
        c.flow(
            "rb.path.traversal", i, args[:1], f"{qualified}()", f"{qualified}() uses a path built from request data."
        )
    elif word == "render" and not member:
        for lo, hi in args:
            if c.ix.name(lo) in ("file", "template") and c.ix.punct(lo + 1, ":"):
                c.flow(
                    "rb.path.traversal",
                    i,
                    [(lo + 2, hi)],
                    "render file:",
                    "render reads a template file chosen by request data.",
                )


_HANDLERS = {"go": _go, "java": _java, "kotlin": _java, "csharp": _csharp, "ruby": _ruby}
