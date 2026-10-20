# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Stream the CVEfixes and MoreFixes dumps into a small private SQLite working database.

CVEfixes ships a SQLite ``.dump`` (``CVEfixes_v1.0.8.sql.gz`` inside the zip); MoreFixes ships a
plain-format PostgreSQL dump whose rows are ``COPY ... FROM stdin`` blocks. Neither is restored in
full. Each statement or row is read once, the row is handed to :class:`Loader`, and only what the
pipeline needs is kept: fixes, commit dates, CVE dates/descriptions, CWEs, and the file and method
changes of Python, JavaScript and TypeScript files. Changed functions in other languages are kept
only as a per-file count (OneFunc needs them). Tables that are not needed (MoreFixes ``users``,
CPE mappings) are skipped without decoding a row.

The dumps are data, never code: SQLite statements run only inside an in-memory staging database,
and only ``CREATE TABLE`` and ``INSERT INTO <table> VALUES`` statements are executed there.
"""

from __future__ import annotations

import gzip
import re
import sqlite3
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .paths import LANGUAGES

Getter = Callable[[str], str | None]

SCHEMA = """
CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT, score INTEGER);
CREATE TABLE commits(hash TEXT, repo_url TEXT, committer_date TEXT);
CREATE TABLE cve(cve_id TEXT, published_date TEXT, description TEXT);
CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
CREATE TABLE file_change(file_change_id TEXT, hash TEXT, old_path TEXT, new_path TEXT, filename TEXT,
  change_type TEXT, language TEXT, diff TEXT, code_before TEXT, code_after TEXT);
CREATE TABLE method_change(file_change_id TEXT, name TEXT, signature TEXT, start_line INTEGER,
  end_line INTEGER, code TEXT, before_change INTEGER);
CREATE TABLE other_functions(hash TEXT, file_change_id TEXT, path TEXT, language TEXT, functions INTEGER);
CREATE TABLE load_stats(key TEXT PRIMARY KEY, value INTEGER);
"""
INDEXES = """
CREATE INDEX fixes_hash ON fixes(hash);
CREATE INDEX fc_hash ON file_change(hash);
CREATE INDEX fc_id ON file_change(file_change_id);
CREATE INDEX mc_fc ON method_change(file_change_id);
CREATE INDEX other_hash ON other_functions(hash);
CREATE INDEX cve_id ON cve(cve_id);
CREATE INDEX cwe_cve ON cwe_classification(cve_id);
"""
INSERTS = {
    "fixes": "INSERT INTO fixes VALUES (?,?,?,?)",
    "commits": "INSERT INTO commits VALUES (?,?,?)",
    "cve": "INSERT INTO cve VALUES (?,?,?)",
    "cwe_classification": "INSERT INTO cwe_classification VALUES (?,?)",
    "file_change": "INSERT INTO file_change VALUES (?,?,?,?,?,?,?,?,?,?)",
    "method_change": "INSERT INTO method_change VALUES (?,?,?,?,?,?,?)",
}
BATCH = 2000
STAGE_FLUSH_BYTES = 64 * 1024 * 1024


class DumpError(RuntimeError):
    pass


def _none(value: str | None) -> str | None:
    return None if value is None or value in {"None", "nan", ""} else value


def _int(value: str | None) -> int | None:
    value = _none(value)
    if value is None:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


class Loader:
    """Receives rows table by table and keeps the filtered subset in ``db``."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        db.executescript(SCHEMA)
        self.rows: Counter[str] = Counter()
        self.files_by_language: Counter[str] = Counter()
        self.methods_by_language: Counter[str] = Counter()
        self.kept_files: dict[str, str] = {}
        self.other: dict[str, tuple[str, str, str, set[str]]] = {}
        self.pending: dict[str, list[tuple[object, ...]]] = {}

    def _add(self, table: str, values: tuple[object, ...]) -> None:
        batch = self.pending.setdefault(table, [])
        batch.append(values)
        if len(batch) >= BATCH:
            self._flush(table)

    def _flush(self, table: str) -> None:
        batch = self.pending.pop(table, [])
        if batch:
            self.db.executemany(INSERTS[table], batch)

    def row(self, table: str, get: Getter) -> None:
        self.rows[table] += 1
        handler = getattr(self, f"_row_{table}", None)
        if handler is not None:
            handler(get)

    def _row_fixes(self, get: Getter) -> None:
        self._add("fixes", (get("cve_id"), get("hash"), get("repo_url"), _int(get("score"))))

    def _row_commits(self, get: Getter) -> None:
        self._add("commits", (get("hash"), get("repo_url"), _none(get("committer_date"))))

    def _row_cve(self, get: Getter) -> None:
        self._add("cve", (get("cve_id"), _none(get("published_date")), _none(get("description"))))

    def _row_cwe_classification(self, get: Getter) -> None:
        self._add("cwe_classification", (get("cve_id"), get("cwe_id")))

    def _row_file_change(self, get: Getter) -> None:
        language = get("programming_language") or "None"
        self.files_by_language[language] += 1
        fc_id = get("file_change_id") or ""
        if language not in LANGUAGES:
            path = _none(get("new_path")) or _none(get("old_path")) or get("filename") or ""
            self.other[fc_id] = (get("hash") or "", path, language, set())
            return
        self.kept_files[fc_id] = language
        self._add(
            "file_change",
            (
                fc_id,
                get("hash"),
                _none(get("old_path")),
                _none(get("new_path")),
                get("filename"),
                get("change_type"),
                LANGUAGES[language],
                _none(get("diff")),
                _none(get("code_before")),
                _none(get("code_after")),
            ),
        )

    def _row_method_change(self, get: Getter) -> None:
        if self.rows["file_change"] == 0:
            raise DumpError("method_change rows precede file_change rows; the loader needs file_change first")
        fc_id = get("file_change_id") or ""
        if fc_id in self.other:
            self.methods_by_language[self.other[fc_id][2]] += 1
            self.other[fc_id][3].add(get("name") or "")
            return
        if fc_id not in self.kept_files:
            self.methods_by_language["unknown_file"] += 1
            return
        self.methods_by_language[self.kept_files[fc_id]] += 1
        before = (get("before_change") or "").strip().lower() in {"true", "t", "1"}
        self._add(
            "method_change",
            (
                fc_id,
                get("name"),
                get("signature"),
                _int(get("start_line")),
                _int(get("end_line")),
                get("code"),
                int(before),
            ),
        )

    def finish(self) -> None:
        for table in list(self.pending):
            self._flush(table)
        self.db.executemany(
            "INSERT INTO other_functions VALUES (?,?,?,?,?)",
            ((h, fc, path, lang, len(names)) for fc, (h, path, lang, names) in self.other.items() if names),
        )
        stats = [(f"rows:{t}", n) for t, n in self.rows.items()]
        stats += [(f"files:{lang}", n) for lang, n in self.files_by_language.items()]
        stats += [(f"methods:{lang}", n) for lang, n in self.methods_by_language.items()]
        self.db.executemany("INSERT INTO load_stats VALUES (?,?)", stats)
        self.db.executescript(INDEXES)
        self.db.commit()


class DictRow:
    """Column getter over one staged SQLite row."""

    def __init__(self, row: dict[str, object]) -> None:
        self.row = row

    def __call__(self, column: str) -> str | None:
        value = self.row.get(column)
        return None if value is None else str(value)


class CopyRow:
    """Column getter over one COPY row; a field is decoded only when asked for."""

    def __init__(self, fields: list[bytes], index: dict[str, int]) -> None:
        self.fields = fields
        self.index = index

    def __call__(self, column: str) -> str | None:
        i = self.index.get(column)
        return None if i is None else copy_value(self.fields[i])


# --- CVEfixes: SQLite text dump -------------------------------------------------------------

CREATE_RE = re.compile(r'^\s*CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?\s*\(', re.IGNORECASE)
INSERT_RE = re.compile(r'^\s*INSERT INTO "?(\w+)"? VALUES\s*\(', re.IGNORECASE)


def sqlite_statements(lines: Iterable[bytes]) -> Iterator[str]:
    """Complete SQL statements from a SQLite ``.dump`` stream.

    A statement can end only at a ``;`` outside a string literal. SQLite dumps quote strings with
    ``'`` and escape a quote by doubling it, so the parity of the quote count tells whether a line
    ends inside a literal. That keeps the scan linear even for files with thousands of lines that
    end in ``;``; ``sqlite3.complete_statement`` confirms each candidate end.
    """
    buf: list[str] = []
    inside = False
    for raw in lines:
        line = raw.decode("utf-8", "replace")
        buf.append(line)
        inside ^= line.count("'") % 2 == 1
        if not inside and line.rstrip().endswith(";"):
            text = "".join(buf)
            if sqlite3.complete_statement(text):  # False only inside a trigger body: keep reading
                yield text
                buf = []
    if "".join(buf).strip():
        raise DumpError("dump ends inside a statement")


def sqlite_rows(lines: Iterable[bytes], wanted: set[str]) -> Iterator[tuple[str, Getter]]:
    """Rows of the ``wanted`` tables, executed in an in-memory staging database."""
    stage = sqlite3.connect(":memory:")
    current: str | None = None
    pending = 0

    def drain(table: str) -> Iterator[tuple[str, Getter]]:
        if table not in WANTED:  # identifiers cannot be bound parameters; allow only our fixed table names
            raise DumpError(f"unexpected staging table {table!r}")
        select = f'SELECT * FROM "{table}"'  # noqa: S608  # kestrix: ignore[py.sql.string_built] table name checked against the fixed WANTED allowlist above
        cursor = stage.execute(select)
        columns = [d[0] for d in cursor.description]
        for values in cursor:
            yield table, DictRow(dict(zip(columns, values, strict=True)))
        delete = f'DELETE FROM "{table}"'  # noqa: S608  # kestrix: ignore[py.sql.string_built] table name checked against the fixed WANTED allowlist above
        stage.execute(delete)

    for statement in sqlite_statements(lines):
        created = CREATE_RE.match(statement)
        if created:
            if created.group(1) in wanted:
                stage.execute(statement)
            continue
        inserted = INSERT_RE.match(statement)
        if not inserted or inserted.group(1) not in wanted:
            continue
        table = inserted.group(1)
        if current not in {None, table} or pending >= STAGE_FLUSH_BYTES:
            yield from drain(current or table)
            pending = 0
        current = table
        stage.execute(statement)
        pending += len(statement)
    if current is not None:
        yield from drain(current)
    stage.close()


# --- MoreFixes: PostgreSQL plain dump with COPY blocks -------------------------------------

COPY_RE = re.compile(rb"^COPY public\.(\w+) \((.*)\) FROM stdin;$")
ESCAPE_RE = re.compile(rb"\\(?:([0-7]{1,3})|x([0-9a-fA-F]{1,2})|(.))", re.DOTALL)
SIMPLE = {b"b": b"\b", b"f": b"\f", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v"}


def _unescape_match(m: re.Match[bytes]) -> bytes:
    if m.group(1) is not None:
        return bytes([int(m.group(1), 8) & 0xFF])
    if m.group(2) is not None:
        return bytes([int(m.group(2), 16)])
    char = m.group(3)
    return SIMPLE.get(char, char)


def copy_value(raw: bytes) -> str | None:
    """Decode one COPY text-format field (``\\N`` is NULL)."""
    if raw == b"\\N":
        return None
    if b"\\" in raw:
        raw = ESCAPE_RE.sub(_unescape_match, raw)
    return raw.decode("utf-8", "replace")


def copy_rows(lines: Iterable[bytes], wanted: set[str]) -> Iterator[tuple[str, Getter]]:
    """Rows of the ``wanted`` tables; fields are decoded lazily, only when asked for."""
    table: str | None = None
    index: dict[str, int] = {}
    for raw in lines:
        # The MoreFixes dump ends lines with CRLF; a CR inside a value is always escaped as \r.
        line = raw[:-2] if raw.endswith(b"\r\n") else raw.rstrip(b"\n")
        if table is None:
            m = COPY_RE.match(line)
            if m:
                name = m.group(1).decode()
                columns = [c.strip().strip('"') for c in m.group(2).decode().split(",")]
                table = name
                index = {c: i for i, c in enumerate(columns)}
            continue
        if line == b"\\.":
            table = None
            continue
        if table not in wanted:
            continue
        fields = line.split(b"\t")
        if len(fields) != len(index):
            raise DumpError(f"{table}: row has {len(fields)} fields, expected {len(index)}")
        yield table, CopyRow(fields, index)
    if table is not None:
        raise DumpError(f"dump ends inside the COPY block of {table}")


WANTED = {"fixes", "commits", "cve", "cwe_classification", "file_change", "method_change"}


@contextmanager
def open_cvefixes(zip_path: Path) -> Iterator[Iterable[bytes]]:
    with zipfile.ZipFile(zip_path) as archive:
        members = [n for n in archive.namelist() if n.endswith(".sql.gz")]
        if len(members) != 1:
            raise DumpError(f"expected one .sql.gz in {zip_path.name}, found {members}")
        with archive.open(members[0]) as member, gzip.GzipFile(fileobj=member) as stream:
            yield stream


@contextmanager
def open_morefixes(gz_path: Path) -> Iterator[Iterable[bytes]]:
    with gzip.open(gz_path, "rb") as stream:
        yield stream


def load(kind: str, path: Path, out: Path) -> dict[str, int]:
    """Stream one dump into a fresh working database at ``out``; return the row counts."""
    tmp = out.with_name(out.name + ".tmp")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    loader = Loader(db)
    opener, reader = (open_cvefixes, sqlite_rows) if kind == "sqlite" else (open_morefixes, copy_rows)
    with opener(path) as stream:
        for table, get in reader(stream, WANTED):
            loader.row(table, get)
    loader.finish()
    db.close()
    tmp.chmod(0o600)
    tmp.replace(out)
    return dict(loader.rows)
