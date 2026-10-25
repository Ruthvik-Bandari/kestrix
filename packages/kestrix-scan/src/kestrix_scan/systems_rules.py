# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""C and C++ (``c.*``), Rust (``rust.*``) and Swift (``swift.*``) rules over ``c_tokens.py``. Source is never run.

The scope is narrow on purpose. Memory-safety bugs (overflows computed from sizes, use after free, integer overflow,
races) need a compiler front-end and a real analyser; these rules only flag patterns that are visible in the tokens of
one file: a banned function (``gets``, ``tmpnam``), a copy into an array declared with a fixed size, a format string
that is not a literal, a shell started with a built command, TLS verification switched off, ``rand()`` next to a
security word, a secret stored in ``UserDefaults``. "No finding" says nothing about memory safety.

Minified files are skipped as ``minified``; files over the tokenizer's bounds as ``too_complex``. Swift's App
Transport Security switch lives in property lists, so ``*.plist`` files are read for it (text plists only).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .c_tokens import tokenize
from .models import Confidence, Severity, SkipReason, clip_snippet
from .php_tokens import ISTR, NAME, PUNCT, STR, Token
from .registry import Hit

C_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"})
RUST_SUFFIXES = frozenset({".rs"})
SWIFT_SUFFIXES = frozenset({".swift"})
PLIST_SUFFIXES = frozenset({".plist"})
SYSTEMS_SUFFIXES = C_SUFFIXES | RUST_SUFFIXES | SWIFT_SUFFIXES | PLIST_SUFFIXES
MAX_AVERAGE_LINE = 500

# ----- C and C++ tables

_COPY_FUNCS = frozenset(
    {"strcpy", "strcat", "wcscpy", "wcscat", "stpcpy", "lstrcpy", "lstrcat", "lstrcpyA", "lstrcpyW", "lstrcatA"}
    | {"lstrcatW", "_tcscpy", "_tcscat", "_mbscpy", "_mbscat", "StrCpy", "StrCat"}
)
_SPRINTF_FUNCS = frozenset({"sprintf", "vsprintf"})
_SHELL_FUNCS = frozenset({"system", "popen", "_popen", "_wsystem", "_wpopen"})
_EXECL_FUNCS = frozenset({"execl", "execlp", "execle"})
# printf-family function -> index of its format argument (the v* forms take a va_list from a caller and are left out)
_FORMAT_ARG: dict[str, int] = {
    "printf": 0,
    "wprintf": 0,
    "fprintf": 1,
    "fwprintf": 1,
    "dprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "swprintf": 2,
    "syslog": 1,
    "err": 1,
    "errx": 1,
    "warn": 0,
    "warnx": 0,
}
_SCANF_ARG: dict[str, int] = {"scanf": 0, "wscanf": 0, "fscanf": 1, "fwscanf": 1, "sscanf": 1, "swscanf": 1}
_RAND_FUNCS = frozenset({"rand", "random", "rand_r", "drand48", "erand48", "lrand48", "nrand48", "mrand48", "jrand48"})
_TEMP_FUNCS = frozenset({"tmpnam", "tmpnam_r", "tempnam", "_tempnam", "_wtempnam", "mktemp", "_mktemp", "_wmktemp"})
_GETTEXT = frozenset({"_", "N_", "gettext", "dgettext", "dcgettext", "ngettext", "_T", "TEXT", "L"})
_STATEMENT_WORDS = frozenset({"return", "else", "do", "case", "throw", "co_return", "co_yield", "sizeof", "not"})
_CONTROL = frozenset({"if", "for", "while", "switch", "catch", "return", "sizeof", "defined", "elif"})
_FUNCTION_TAIL = frozenset({"const", "noexcept", "override", "final", "mutable", "volatile"})
_PRINTF_CONVERSION = re.compile(r"%(?:%|[-+ #0']*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|q|j|z|t|I64|I32|I)?([a-zA-Z]))")
_SCANF_CONVERSION = re.compile(r"%(?:%|(\*)?(\d+)?(m)?(?:hh|h|ll|l|L|q|j|z|t)?(\[|[a-zA-Z]))")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "/k", "/K", "-Command", "-command", "-EncodedCommand"})
_SECURITY_WORDS = frozenset(
    {"key", "keys", "token", "tokens", "password", "passwd", "pwd", "secret", "nonce", "salt", "session", "sid"}
    | {"cookie", "csrf", "xsrf", "otp", "auth", "crypt", "crypto", "encrypt", "cipher", "iv", "challenge", "uuid"}
    | {"guid", "keygen", "passphrase"}
)
_LITERAL_MACRO = re.compile(r"(?:PRI|SCN)\w+$|[A-Z][A-Z0-9_]*$|L$|u8$")  # PRIu64, a constant
_WORD_SPLIT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

# ----- Rust tables

_RUST_UNCHECKED = frozenset(
    {"get_unchecked", "get_unchecked_mut", "from_raw_parts", "from_raw_parts_mut", "set_len", "copy_nonoverlapping"}
    | {"copy", "copy_from", "copy_to", "copy_from_nonoverlapping", "copy_to_nonoverlapping", "write_bytes", "offset"}
    | {"add"}
)
_RUST_INPUT_TYPES = frozenset({"u8", "i8", "str", "String", "Read", "BufRead", "Bytes", "BytesMut", "Buf", "OsStr"})
_RUST_SOURCES = frozenset(
    {"args", "args_os", "var", "var_os", "vars", "stdin", "read", "read_exact", "read_to_end", "read_to_string"}
    | {"read_line", "recv", "recv_from", "peek"}
)
_RUST_LITERAL_NAMES = frozenset({"to_string", "to_owned", "into", "String", "from", "OsStr", "new", "as_ref"})
_RUST_TLS_CALLS = frozenset({"danger_accept_invalid_certs", "danger_accept_invalid_hostnames"})
_RUSTLS_TRUST_ALL = frozenset({"Ok", "ServerCertVerified", "assertion", "rustls", "client", "danger", "crate", "self"})
_FORMAT_HOLE = re.compile(r"\{[A-Za-z_]")

# ----- Swift tables

_SWIFT_TRUST_CHECK = re.compile(r"^Sec[A-Z]|[Pp]in|[Ee]valuat|[Vv]alidat|[Vv]erif")
_SWIFT_DISABLED_EVALUATORS = frozenset({"DisabledTrustEvaluator", "DisabledEvaluator", "disableEvaluation"})
_SWIFT_ANY_CERT = frozenset({"allowsAnyHTTPSCertificate", "setAllowsAnyHTTPSCertificate"})
_SECRET_KEY = re.compile(
    r"password|passwd|passcode|secret|apikey|privatekey|credential|accesstoken|refreshtoken|authtoken|bearer|sessiontoken|(?:^|[^a-z])token$|^token"
)
_NOT_SECRET_KEY = re.compile(r"devicetoken|pushtoken|fcmtoken|apnstoken|notificationtoken")
_ATS = re.compile(
    r"<key>\s*(NSAllowsArbitraryLoads|NSAllowsArbitraryLoadsInWebContent|NSAllowsArbitraryLoadsForMedia"
    r"|NSExceptionAllowsInsecureHTTPLoads|NSTemporaryExceptionAllowsInsecureHTTPLoads)\s*</key>\s*<true\s*/>"
)


def minified(text: str) -> bool:
    return len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE


def check_systems(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one C/C++, Rust, Swift or property-list file, or the reason it was not analyzed."""
    lowered = rel.lower()
    lines = text.splitlines()
    if lowered.endswith(".plist"):
        return _plist(text, lines)
    if minified(text):
        return "minified"
    language = "c" if lowered.endswith(tuple(C_SUFFIXES)) else "rust" if lowered.endswith(".rs") else "swift"
    tokens = tokenize(text, language)
    if tokens is None:
        return "too_complex"
    code = _Code(tokens, lines)
    checker = {"c": _check_c, "rust": _check_rust, "swift": _check_swift}[language]
    return _unique(list(checker(code)))


def _unique(hits: list[Hit]) -> list[Hit]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Hit] = []
    for item in hits:
        key = (item.rule_id, item.line, item.column)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


class _Code:
    """Tokens with their matching brackets, and helpers shared by the three languages."""

    def __init__(self, tokens: list[Token], lines: list[str]) -> None:
        self.toks = tokens
        self.lines = lines
        self.match = [-1] * len(tokens)
        stack: list[int] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        for i, tok in enumerate(tokens):
            if tok.kind != PUNCT:
                continue
            if tok.value in "([{":
                stack.append(i)
            elif tok.value in pairs and stack and tokens[stack[-1]].value == pairs[tok.value]:
                j = stack.pop()
                self.match[i] = j
                self.match[j] = i

    def value(self, i: int) -> str:
        return self.toks[i].value if 0 <= i < len(self.toks) else ""

    def is_punct(self, i: int, value: str) -> bool:
        return 0 <= i < len(self.toks) and self.toks[i].kind == PUNCT and self.toks[i].value == value

    def args(self, open_idx: int) -> list[tuple[int, int]]:
        """Top-level argument ranges [start, end) of the bracket opened at ``open_idx``."""
        close = self.match[open_idx]
        if close < 0:
            return []
        out: list[tuple[int, int]] = []
        start = open_idx + 1
        k = start
        while k < close:
            tok = self.toks[k]
            if tok.kind == PUNCT and tok.value in "([{" and self.match[k] > k:
                k = self.match[k] + 1
                continue
            if tok.kind == PUNCT and tok.value == ",":
                out.append((start, k))
                start = k + 1
            k += 1
        if start < close or out:
            out.append((start, close))
        return out

    def text(self, start: int, end: int) -> str:
        return " ".join(t.value for t in self.toks[start:end])

    def hit(
        self,
        rule: str,
        at: int,
        message: str,
        *,
        end: int | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> Hit:
        tok = self.toks[at]
        last = self.toks[end - 1].end_line if end is not None and end > at else tok.end_line
        source = self.lines[tok.line - 1] if 0 < tok.line <= len(self.lines) else ""
        return Hit(rule, tok.line, tok.col, max(last, tok.line), message, clip_snippet(source), severity, confidence)


def _names(code: _Code, start: int, end: int) -> set[str]:
    return {t.value for t in code.toks[start:end] if t.kind == NAME}


def _words(name: str) -> set[str]:
    return {w.lower() for part in name.split("_") for w in _WORD_SPLIT.findall(part)}


# ----- C and C++


def _directive_lines(lines: list[str]) -> set[int]:
    """Line numbers of preprocessor directives, with their backslash continuations."""
    out: set[int] = set()
    inside = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if inside or stripped.startswith("#"):
            out.add(number)
            inside = stripped.endswith("\\")
    return out


def _c_call(code: _Code, i: int) -> bool:
    """``tokens[i]`` is a name called as a plain function (not a member, a declaration or a macro definition)."""
    if code.toks[i].kind != NAME or not code.is_punct(i + 1, "("):
        return False
    prev = code.toks[i - 1] if i > 0 else None
    if prev is None:
        return True
    if prev.kind == PUNCT and prev.value in {".", "->"}:
        return False
    if prev.kind == PUNCT and prev.value == "::":
        return code.value(i - 2) == "std" or i < 2 or code.toks[i - 2].kind == PUNCT
    if prev.kind == NAME:
        return prev.value in _STATEMENT_WORDS
    if prev.kind == PUNCT and prev.value in {"*", "&"} and i > 1:
        before = code.toks[i - 2]
        return not (before.kind == NAME and before.value not in _STATEMENT_WORDS) and before.value != "*"
    return True


def _c_literal(code: _Code, start: int, end: int) -> bool:
    """The argument is a string literal: adjacent literals, macro names between them (PRIu64), a gettext call of a
    literal, or one of those in parentheses."""
    toks = code.toks[start:end]
    while len(toks) >= 2 and toks[0].value == "(" and toks[-1].value == ")" and code.match[start] == end - 1:
        start, end = start + 1, end - 1
        toks = toks[1:-1]
    if not toks:
        return False
    if toks[0].kind == NAME and toks[0].value in _GETTEXT and len(toks) >= 3 and toks[1].value == "(":
        inner = [t for t in toks[2:-1] if t.kind != PUNCT or t.value != ","]
        return bool(inner) and inner[0].kind == STR
    has_str = any(t.kind == STR for t in toks)
    return has_str and all(
        t.kind == STR or (t.kind == NAME and _LITERAL_MACRO.match(t.value) is not None) for t in toks
    )


def _macro_constant(code: _Code, start: int, end: int) -> bool:
    toks = code.toks[start:end]
    return len(toks) == 1 and toks[0].kind == NAME and toks[0].value.isupper() and len(toks[0].value) > 1


def _literal_value(code: _Code, start: int, end: int) -> str:
    return "".join(t.value for t in code.toks[start:end] if t.kind == STR)


def _fixed_arrays(code: _Code) -> set[str]:
    """Names declared as arrays with a size in this file: ``char buf[64];``, ``char name[IFNAMSIZ + 1] = ...``."""
    out: set[str] = set()
    toks = code.toks
    for i in range(1, len(toks) - 2):
        tok = toks[i]
        if tok.kind != NAME or not code.is_punct(i + 1, "["):
            continue
        close = code.match[i + 1]
        if close <= i + 2:
            continue
        prev = toks[i - 1]
        after = code.value(close + 1)
        if prev.kind == NAME and prev.value not in _STATEMENT_WORDS and after in {";", "=", "[", ",", ")"}:
            out.add(tok.value)
    return out


def _dest_name(code: _Code, start: int, end: int) -> str | None:
    """The array a destination names: ``buf``, ``&buf[0]``, ``s->name``, ``buf + len``; None for anything else."""
    toks = code.toks
    k = start
    if k < end and toks[k].value == "&":
        k += 1
    if k >= end or toks[k].kind != NAME:
        return None
    name = toks[k].value
    k += 1
    while k + 1 < end and toks[k].value in {".", "->"} and toks[k + 1].kind == NAME:
        name = toks[k + 1].value
        k += 2
    if k < end and toks[k].value == "[" and code.match[k] > 0:
        k = code.match[k] + 1
    if k == end or toks[k].value in {"+", "-"}:
        return name
    return None


def _literal_assigned(code: _Code) -> set[str]:
    """Names that are only ever assigned string literals in this file (``const char *fmt = "...";``)."""
    good: set[str] = set()
    bad: set[str] = set()
    toks = code.toks
    for i in range(len(toks) - 2):
        if toks[i].kind != NAME or not code.is_punct(i + 1, "="):
            if toks[i].kind == NAME and code.is_punct(i + 1, "[") and code.match[i + 1] > 0:
                close = code.match[i + 1]
                if code.is_punct(close + 1, "=") and code.value(close + 2) and toks[close + 2].kind == STR:
                    good.add(toks[i].value)
            continue
        k = i + 2
        while k < len(toks) and toks[k].kind == STR:
            k += 1
        if k > i + 2 and code.value(k) in {";", ","}:
            good.add(toks[i].value)
        else:
            bad.add(toks[i].value)
    return good - bad


def _c_functions(code: _Code) -> list[tuple[str, int, int]]:
    """(name, body open, body close) of function definitions, outermost only."""
    out: list[tuple[str, int, int]] = []
    toks = code.toks
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok.kind == PUNCT and tok.value == "{" and code.match[i] > i:
            k = i - 1
            while k >= 0 and toks[k].kind == NAME and toks[k].value in _FUNCTION_TAIL:
                k -= 1
            if k >= 0 and code.is_punct(k, ")") and code.match[k] > 0:
                opener = code.match[k]
                name = code.value(opener - 1)
                if toks[opener - 1].kind == NAME and name not in _CONTROL:
                    out.append((name, i, code.match[i]))
                    i = code.match[i] + 1
                    continue
        i += 1
    return out


def _enclosing(functions: list[tuple[str, int, int]], i: int) -> str:
    for name, start, end in functions:
        if start < i < end:
            return name
    return ""


def _statement(code: _Code, i: int) -> tuple[int, int]:
    """[start, end) of the statement around token ``i`` (from the last ``;``, ``{`` or ``}`` to the next ``;``)."""
    start = i
    while start > 0 and code.value(start - 1) not in {";", "{", "}"}:
        start -= 1
    end = i
    while end < len(code.toks) and code.value(end) not in {";", "{", "}"}:
        end += 1
    return start, end


def _check_c(code: _Code) -> Iterator[Hit]:
    toks = code.toks
    skip_lines = _directive_lines(code.lines)
    arrays = _fixed_arrays(code)
    literal_names = _literal_assigned(code)
    functions = _c_functions(code)
    for i, tok in enumerate(toks):
        if tok.kind != NAME or tok.line in skip_lines or not _c_call(code, i):
            continue
        name = tok.value
        args = code.args(i + 1)
        end = code.match[i + 1] + 1
        if name == "gets":
            yield code.hit("c.buffer.gets", i, "gets() reads a line of any length into a fixed buffer.", end=end)
        if name in _TEMP_FUNCS:
            yield code.hit(
                "c.tempfile.insecure", i, f"{name}() makes a name another process can create first.", end=end
            )
        if name in _COPY_FUNCS or name in _SPRINTF_FUNCS:
            yield from _c_copy(code, i, name, args, arrays=arrays, end=end)
        if name in _SHELL_FUNCS and args and not _c_literal(code, *args[0]) and not _macro_constant(code, *args[0]):
            yield code.hit(
                "c.exec.command", i, f"{name}() runs a command string built at run time through the shell.", end=end
            )
        if name in _EXECL_FUNCS:
            yield from _c_execl(code, i, name, args, end)
        if name in _FORMAT_ARG:
            yield from _c_format(code, i, name, args, literal_names=literal_names, end=end)
        if name in _SCANF_ARG and len(args) > _SCANF_ARG[name] and _c_literal(code, *args[_SCANF_ARG[name]]):
            fmt = _literal_value(code, *args[_SCANF_ARG[name]])
            for match in _SCANF_CONVERSION.finditer(fmt):
                star, width, alloc, conv = match.groups()
                if conv in {"s", "["} and not star and not width and not alloc:
                    yield code.hit(
                        "c.input.scanf_string",
                        i,
                        f"{name}() reads %{conv} without a field width, so a long word overflows the buffer.",
                        end=end,
                    )
                    break
        if name in _RAND_FUNCS:
            start, stop = _statement(code, i)
            context = _names(code, start, stop) | {_enclosing(functions, i)}
            if any(_words(n) & _SECURITY_WORDS for n in context if n):
                yield code.hit(
                    "c.random.rand",
                    i,
                    f"{name}() is a predictable generator, used here next to a security value.",
                    end=end,
                )


def _c_copy(
    code: _Code, i: int, name: str, args: list[tuple[int, int]], *, arrays: set[str], end: int
) -> Iterator[Hit]:
    if len(args) < 2:
        return
    dest = _dest_name(code, *args[0])
    if dest is None or dest not in arrays:
        return
    if name in _COPY_FUNCS:
        if _c_literal(code, *args[1]):
            return
        yield code.hit(
            "c.buffer.unbounded_copy",
            i,
            f"{name}() copies a string of unchecked length into the fixed-size array '{dest}'.",
            end=end,
        )
        return
    fmt_range = args[1]
    if not _c_literal(code, *fmt_range):
        yield code.hit(
            "c.buffer.unbounded_copy",
            i,
            f"{name}() writes a format that is not a literal into the fixed-size array '{dest}' without a size limit.",
            end=end,
        )
        return
    if name == "vsprintf":
        return
    position = 2
    for match in _PRINTF_CONVERSION.finditer(_literal_value(code, *fmt_range)):
        width, precision, conv = match.groups()
        if conv is None:
            continue
        position += (width == "*") + (precision == "*")
        if (
            conv in {"s", "S"}
            and precision is None
            and (position >= len(args) or not _c_literal(code, *args[position]))
        ):
            yield code.hit(
                "c.buffer.unbounded_copy",
                i,
                f"{name}() writes a %s of unchecked length into the fixed-size array '{dest}'.",
                end=end,
            )
            return
        position += 1


def _c_execl(code: _Code, i: int, name: str, args: list[tuple[int, int]], end: int) -> Iterator[Hit]:
    """``execl("/bin/sh", "sh", "-c", command, NULL)`` with a command that is not a literal."""
    if len(args) < 4 or not _c_literal(code, *args[0]):
        return
    program = _literal_value(code, *args[0]).rsplit("/", 1)[-1]
    if program not in _SHELLS:
        return
    for k, arg in enumerate(args[1:-1], start=1):
        if _c_literal(code, *arg) and _literal_value(code, *arg) in _SHELL_FLAGS:
            script = args[k + 1] if k + 1 < len(args) else None
            if script and not _c_literal(code, *script) and code.text(*script) not in {"NULL", "0", "nullptr"}:
                yield code.hit(
                    "c.exec.command", i, f"{name}() starts a shell with a script built at run time.", end=end
                )
            return


def _c_format(
    code: _Code, i: int, name: str, args: list[tuple[int, int]], *, literal_names: set[str], end: int
) -> Iterator[Hit]:
    index = _FORMAT_ARG[name]
    if len(args) != index + 1:  # a format followed by arguments is usually a deliberate pass-through
        return
    start, stop = args[index]
    if stop <= start or _c_literal(code, start, stop) or _macro_constant(code, start, stop):
        return
    if stop - start == 1 and code.toks[start].value in literal_names:
        return
    yield code.hit(
        "c.format.nonliteral",
        i,
        f"{name}() takes its format string from '{code.text(start, stop)[:60]}', which is not a literal.",
        end=end,
    )


# ----- Rust


def _rust_functions(code: _Code) -> list[tuple[int, int, int, int]]:
    """(name, ``(`` of the parameter list, body open, body close) token indexes of each ``fn`` with a body, nested ones
    included."""
    out: list[tuple[int, int, int, int]] = []
    toks = code.toks
    for i, tok in enumerate(toks):
        if tok.kind != NAME or tok.value != "fn":
            continue
        k = i + 1
        while k < len(toks) and not code.is_punct(k, "(") and code.value(k) not in {";", "{"}:
            k += 1
        if not code.is_punct(k, "(") or code.match[k] < 0:
            continue
        params = k
        k = code.match[k] + 1
        while k < len(toks) and code.value(k) not in {"{", ";"}:
            if toks[k].kind == PUNCT and toks[k].value in "([" and code.match[k] > k:
                k = code.match[k]
            k += 1
        if code.is_punct(k, "{") and code.match[k] > k:
            out.append((i + 1, params, k, code.match[k]))
    return out


def _rust_tainted(code: _Code, params: int, body: int, close: int) -> set[str]:
    """Names in one function that carry external input: byte, string or reader parameters, values read from the
    environment, stdin or a reader, and ``let`` bindings computed from any of those."""
    tainted: set[str] = set()
    for start, stop in code.args(params):
        names = [t for t in code.toks[start:stop] if t.kind == NAME and t.value not in {"mut", "ref", "self"}]
        colon = next((k for k in range(start, stop) if code.is_punct(k, ":")), -1)
        if names and colon > 0 and _names(code, colon, stop) & _RUST_INPUT_TYPES:
            tainted.add(names[0].value)
    toks = code.toks
    lets: list[tuple[set[str], set[str]]] = []
    for k in range(body + 1, close):
        if toks[k].kind == NAME and toks[k].value == "let":
            eq = k + 1
            while eq < close and code.value(eq) not in {"=", ";"}:
                eq += 1
            if code.value(eq) != "=":
                continue
            stop = eq + 1
            while stop < close and code.value(stop) != ";":
                if toks[stop].kind == PUNCT and toks[stop].value in "([{" and code.match[stop] > stop:
                    stop = code.match[stop]
                stop += 1
            bound = {t.value for t in toks[k + 1 : eq] if t.kind == NAME and t.value not in {"mut", "ref"}}
            used = _names(code, eq + 1, stop)
            if used & _RUST_SOURCES:
                tainted |= bound
            lets.append((bound, used))
        elif toks[k].kind == NAME and toks[k].value in _RUST_SOURCES and code.is_punct(k + 1, "("):
            for start, stop in code.args(k + 1):  # reader.read(&mut buf): the buffer now holds input
                tainted |= {t.value for t in toks[start:stop] if t.kind == NAME and t.value not in {"mut"}}
    for _ in range(4):
        before = len(tainted)
        for bound, used in lets:
            if used & tainted:
                tainted |= bound
        if len(tainted) == before:
            break
    return tainted


def _check_rust(code: _Code) -> Iterator[Hit]:
    toks = code.toks
    functions = _rust_functions(code)
    for i, tok in enumerate(toks):
        if tok.kind != NAME:
            continue
        if tok.value in _RUST_TLS_CALLS and code.is_punct(i + 1, "(") and code.value(i + 2) == "true":
            yield code.hit("rust.tls.disabled", i, f"{tok.value}(true) accepts any certificate or host name.")
        elif tok.value == "SslVerifyMode" and code.value(i + 1) == "::" and code.value(i + 2) == "NONE":
            yield code.hit("rust.tls.disabled", i, "SslVerifyMode::NONE turns certificate verification off.")
        elif tok.value == "set_verify_hostname" and code.is_punct(i + 1, "(") and code.value(i + 2) == "false":
            yield code.hit("rust.tls.disabled", i, "set_verify_hostname(false) accepts a certificate for any host.")
        elif tok.value == "Command" and code.value(i + 1) == "::" and code.value(i + 2) == "new":
            yield from _rust_shell(code, i, functions)
    for name, params, body, close in functions:
        if code.value(name) == "verify_server_cert":
            names = _names(code, body + 1, close)
            if "assertion" in names and names <= _RUSTLS_TRUST_ALL:
                yield code.hit("rust.tls.disabled", name, "This certificate verifier accepts every certificate.")
        tainted: set[str] | None = None
        for k in range(body + 1, close):
            if toks[k].kind != NAME or toks[k].value != "unsafe" or not code.is_punct(k + 1, "{"):
                continue
            if tainted is None:
                tainted = _rust_tainted(code, params, body, close)
            if not tainted:
                break
            block_end = code.match[k + 1]
            for j in range(k + 2, block_end):
                if toks[j].kind == NAME and toks[j].value in _RUST_UNCHECKED and code.is_punct(j + 1, "("):
                    used = _names(code, j + 2, code.match[j + 1]) & tainted
                    if toks[j].value in {"add", "offset", "copy"} and code.value(j - 1) not in {".", "::"}:
                        continue
                    if used:
                        yield code.hit(
                            "rust.unsafe.input",
                            j,
                            f"{toks[j].value}() in an unsafe block takes '{sorted(used)[0]}', which comes from input this function reads, without a bounds check the compiler enforces.",
                            end=code.match[j + 1] + 1,
                        )


def _rust_items(code: _Code, start: int, stop: int) -> list[tuple[int, int]]:
    """The values of one ``.arg(x)`` or ``.args([a, b])`` call."""
    toks = code.toks[start:stop]
    k = start
    while k < stop and code.value(k) in {"&", "vec", "!"}:
        k += 1
    if k < stop and code.value(k) == "[" and code.match[k] == stop - 1:
        return code.args(k)
    return [(start, stop)] if toks else []


def _rust_literal(code: _Code, start: int, stop: int) -> bool:
    toks = code.toks[start:stop]
    if not any(t.kind == STR for t in toks):
        return False
    if any(t.kind == STR and _FORMAT_HOLE.search(t.value) for t in toks) and "format" in _names(code, start, stop):
        return False
    return all(t.kind in {STR, PUNCT} or t.value in _RUST_LITERAL_NAMES for t in toks)


def _rust_shell(code: _Code, i: int, functions: list[tuple[int, int, int, int]]) -> Iterator[Hit]:
    """``Command::new("sh")`` with ``-c`` and then a value that is not a literal, in one chain or on the variable the
    command is bound to."""
    if not code.is_punct(i + 3, "("):
        return
    program_args = code.args(i + 3)
    if len(program_args) != 1 or not _rust_literal(code, *program_args[0]):
        return
    program = "".join(t.value for t in code.toks[program_args[0][0] : program_args[0][1]] if t.kind == STR)
    if program.rsplit("/", 1)[-1] not in _SHELLS:
        return
    calls = list(_chain(code, code.match[i + 3] + 1))
    bound = code.value(i - 2) if code.value(i - 1) == "=" else ""
    if bound and code.toks[i - 2].kind == NAME:
        scope_end = min((close for _, _, body, close in functions if body < i < close), default=len(code.toks))
        for k in range(code.match[i + 3] + 1, scope_end):
            if code.toks[k].kind == NAME and code.toks[k].value == bound and code.value(k + 1) == ".":
                calls += list(_chain(code, k + 1))
    seen_flag = False
    for method, open_idx in calls:
        if method not in {"arg", "args"}:
            continue
        for start, stop in _rust_items(code, open_idx + 1, code.match[open_idx]):
            literal = _rust_literal(code, start, stop)
            if seen_flag and not literal:
                yield code.hit(
                    "rust.exec.shell",
                    start,
                    f"A shell ({program}) runs a script built from '{code.text(start, stop)[:60]}'.",
                    end=stop,
                )
                return
            if literal and "".join(t.value for t in code.toks[start:stop] if t.kind == STR) in _SHELL_FLAGS:
                seen_flag = True


def _chain(code: _Code, k: int) -> Iterator[tuple[str, int]]:
    """(method, index of its ``(``) for each ``.method(...)`` call chained from token ``k``."""
    while (
        code.value(k) == "." and code.toks[k + 1].kind == NAME and code.is_punct(k + 2, "(") and code.match[k + 2] > 0
    ):
        yield code.toks[k + 1].value, k + 2
        k = code.match[k + 2] + 1
        while code.value(k) == "?":
            k += 1


# ----- Swift


def _swift_functions(code: _Code) -> list[tuple[int, int, int]]:
    """(``(`` of the parameter list, body open, body close) of each ``func`` with a body."""
    out: list[tuple[int, int, int]] = []
    toks = code.toks
    for i, tok in enumerate(toks):
        if tok.kind != NAME or tok.value != "func":
            continue
        k = i + 1
        while k < len(toks) and not code.is_punct(k, "(") and code.value(k) not in {"{", "}"}:
            k += 1
        if not code.is_punct(k, "(") or code.match[k] < 0:
            continue
        params = k
        k = code.match[k] + 1
        while k < len(toks) and code.value(k) not in {"{", "}"}:
            if toks[k].kind == PUNCT and toks[k].value in "([" and code.match[k] > k:
                k = code.match[k]
            k += 1
        if code.is_punct(k, "{") and code.match[k] > k:
            out.append((params, k, code.match[k]))
    return out


def _secret_key(value: str) -> bool:
    key = re.sub(r"[^a-z0-9]", "", value.lower())
    return bool(_SECRET_KEY.search(key)) and not _NOT_SECRET_KEY.search(key)


def _check_swift(code: _Code) -> Iterator[Hit]:
    toks = code.toks
    for params, body, close in _swift_functions(code):
        names = _names(code, params, code.match[params])
        if not {"didReceive", "challenge"} <= names and "URLAuthenticationChallenge" not in names:
            continue
        inside = _names(code, body + 1, close)
        if any(_SWIFT_TRUST_CHECK.search(n) for n in inside):
            continue
        for k in range(body + 1, close - 3):
            if (
                toks[k].value == "URLCredential"
                and code.is_punct(k + 1, "(")
                and code.value(k + 2) == "trust"
                and code.value(k + 3) == ":"
            ):
                yield code.hit(
                    "swift.tls.trust_all",
                    k,
                    "This authentication challenge handler accepts the server's certificate without evaluating it.",
                )
                break
    for i, tok in enumerate(toks):
        if tok.kind != NAME:
            continue
        if tok.value in _SWIFT_DISABLED_EVALUATORS or tok.value in _SWIFT_ANY_CERT:
            if code.value(i - 1) in {"class", "struct", "func", "enum", "case"}:
                continue
            yield code.hit("swift.tls.trust_all", i, f"{tok.value} accepts any server certificate.")
        elif tok.value in {"set", "setValue", "setObject"} and code.is_punct(i + 1, "(") and code.value(i - 1) == ".":
            yield from _swift_defaults(code, i)
        elif tok.value == "AppStorage" and code.value(i - 1) == "@" and code.is_punct(i + 1, "("):
            first = code.toks[i + 2] if i + 2 < len(toks) else None
            if first is not None and first.kind in {STR, ISTR} and _secret_key(first.value):
                yield code.hit(
                    "swift.storage.userdefaults_secret",
                    i,
                    f'@AppStorage("{first.value[:40]}") keeps a secret in UserDefaults, a plain property list on disk.',
                )


def _swift_defaults(code: _Code, i: int) -> Iterator[Hit]:
    """``UserDefaults.standard.set(token, forKey: "authToken")`` (or a receiver named like ``defaults``)."""
    k = i - 2
    receiver: list[str] = []
    while k >= 0 and code.toks[k].kind == NAME:
        receiver.append(code.toks[k].value)
        if code.value(k - 1) != ".":
            break
        k -= 2
    if not any(n == "UserDefaults" or "defaults" in n.lower() for n in receiver):
        return
    for start, stop in code.args(i + 1):
        if code.value(start) == "forKey" and code.value(start + 1) == ":" and stop == start + 3:
            key = code.toks[start + 2]
            if key.kind == STR and _secret_key(key.value):
                yield code.hit(
                    "swift.storage.userdefaults_secret",
                    i,
                    f"UserDefaults stores '{key.value[:40]}' unencrypted in the app's preferences file.",
                    end=code.match[i + 1] + 1,
                )


# ----- property lists


def _plist(text: str, lines: list[str]) -> list[Hit]:
    hits: list[Hit] = []
    if "Allows" not in text:
        return hits
    line, counted = 1, 0
    for match in _ATS.finditer(text):
        line += text.count("\n", counted, match.start())
        counted = match.start()
        key = match.group(1)
        exception = "Exception" in key
        hits.append(
            Hit(
                "swift.ats.arbitrary_loads",
                line,
                match.start() - text.rfind("\n", 0, match.start()),
                line + text.count("\n", match.start(), match.end()),
                f"{key} is true: App Transport Security allows plain HTTP"
                + (" for this domain." if exception else " and weak TLS for every connection."),
                clip_snippet(lines[line - 1] if 0 < line <= len(lines) else ""),
                severity="low" if exception else None,
            )
        )
    return hits
