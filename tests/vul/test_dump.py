# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import gzip
import io
import sqlite3
import zipfile
from pathlib import Path

import pytest

from kestrixvul.dump import DumpError, Loader, copy_rows, copy_value, load, sqlite_rows, sqlite_statements

SQLITE_DUMP = """PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "fixes" ("cve_id" TEXT, "hash" TEXT, "repo_url" TEXT);
INSERT INTO fixes VALUES('CVE-2020-0001','aaa','https://github.com/o/p');
CREATE TABLE IF NOT EXISTS "file_change" ("file_change_id" TEXT, "hash" TEXT, "filename" TEXT, "old_path" TEXT,
 "new_path" TEXT, "change_type" TEXT, "diff" TEXT, "code_before" TEXT, "code_after" TEXT, "programming_language" TEXT);
INSERT INTO file_change VALUES('f1','aaa','a.py','a.py','a.py','ModificationType.MODIFY','@@ -1 +1 @@
-x;
+y','def f():
    return 1;','def f():
    return 2','Python');
INSERT INTO "file_change" VALUES('f2','aaa','b.c','b.c','b.c','MODIFY',replace('d\\n','\\n',char(10)),'int x;','int y;','C');
CREATE TABLE IF NOT EXISTS "method_change" ("method_change_id" TEXT, "file_change_id" TEXT, "name" TEXT,
 "signature" TEXT, "parameters" TEXT, "start_line" INTEGER, "end_line" INTEGER, "code" TEXT, "before_change" TEXT);
INSERT INTO method_change VALUES('m1','f1','f','f()','[]',1,2,'def f():
    return 1;','True');
INSERT INTO method_change VALUES('m2','f2','g','g()','[]',1,1,'int g;','False');
INSERT INTO method_change VALUES('m3','f2','h','h()','[]',2,2,'int h;','True');
CREATE TABLE IF NOT EXISTS "users" ("id" TEXT, "hashed_password" TEXT);
INSERT INTO users VALUES('u','never-read');
COMMIT;
"""


def _lines(text: str) -> list[bytes]:
    return io.BytesIO(text.encode()).readlines()


def test_sqlite_statements_join_multiline_literals_ending_in_semicolons():
    statements = list(sqlite_statements(_lines(SQLITE_DUMP)))
    file_insert = next(s for s in statements if s.startswith("INSERT INTO file_change"))
    assert "return 1;" in file_insert and file_insert.rstrip().endswith(");")


def test_sqlite_statements_reject_a_truncated_dump():
    with pytest.raises(DumpError):
        list(sqlite_statements(_lines("INSERT INTO t VALUES('open\n")))


def test_sqlite_rows_execute_only_wanted_tables_in_a_staging_database():
    rows = [(t, g("file_change_id"), g("diff")) for t, g in sqlite_rows(_lines(SQLITE_DUMP), {"file_change"})]
    assert [r[0] for r in rows] == ["file_change", "file_change"]
    assert rows[1][2] == "d\n"  # replace(..., char(10)) is evaluated by SQLite, not by us


def test_copy_value_decodes_postgres_text_escapes():
    assert copy_value(b"\\N") is None
    assert copy_value(b"a\\tb\\nc\\\\d") == "a\tb\nc\\d"
    assert copy_value(b"\\101\\x42") == "AB"


def test_copy_rows_skip_unwanted_tables_and_check_field_counts():
    dump = (
        b"COPY public.users (id, hashed_password) FROM stdin;\nu\tsecret\n\\.\n"
        b"COPY public.fixes (cve_id, hash, repo_url, score) FROM stdin;\nCVE-1\th\thttps://github.com/o/p\t80\n\\.\n"
    )
    rows = [(t, g("cve_id"), g("score"), g("missing")) for t, g in copy_rows(io.BytesIO(dump), {"fixes"})]
    assert rows == [("fixes", "CVE-1", "80", None)]
    crlf = b"COPY public.fixes (cve_id, hash) FROM stdin;\r\nCVE-2\tab\\r\r\n\\.\r\n"
    assert [(g("cve_id"), g("hash")) for _, g in copy_rows(io.BytesIO(crlf), {"fixes"})] == [("CVE-2", "ab\r")]
    with pytest.raises(DumpError, match="fields"):
        list(copy_rows(io.BytesIO(b"COPY public.fixes (a, b) FROM stdin;\nonly-one\n\\.\n"), {"fixes"}))
    with pytest.raises(DumpError, match="ends inside"):
        list(copy_rows(io.BytesIO(b"COPY public.fixes (a) FROM stdin;\nx\n"), {"fixes"}))


def test_loader_keeps_target_languages_and_counts_other_functions(tmp_path: Path):
    archive = tmp_path / "CVEfixes.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("CVEfixes/Data/CVEfixes.sql.gz", gzip.compress(SQLITE_DUMP.encode()))
    out = tmp_path / "work.sqlite"
    rows = load("sqlite", archive, out)
    assert rows["file_change"] == 2 and "users" not in rows
    db = sqlite3.connect(out)
    assert db.execute("SELECT file_change_id, language FROM file_change").fetchall() == [("f1", "python")]
    assert db.execute("SELECT name, before_change FROM method_change").fetchall() == [("f", 1)]
    assert db.execute("SELECT hash, path, language, functions FROM other_functions").fetchall() == [
        ("aaa", "b.c", "C", 2)
    ]
    stats = dict(db.execute("SELECT key, value FROM load_stats"))
    assert stats["files:Python"] == 1 and stats["files:C"] == 1 and stats["methods:C"] == 2
    assert out.stat().st_mode & 0o777 == 0o600


def test_loader_refuses_methods_before_files():
    loader = Loader(sqlite3.connect(":memory:"))
    with pytest.raises(DumpError, match="precede"):
        loader.row("method_change", lambda c: None)
