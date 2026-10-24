# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 2: rules for ``.sql`` files and the bounded statement reader. A positive and a negative case for every rule."""

import textwrap
import time
from pathlib import Path

from kestrix_scan.analyze import scan_text
from kestrix_scan.registry import Hit
from kestrix_scan.sql_rules import MAX_STATEMENTS, check_sql, statements
from kestrix_scan.walk import Candidate


def hits(body: str) -> list[Hit]:
    result = check_sql(textwrap.dedent(body), "db/schema.sql")
    assert isinstance(result, list), result
    return result


def ids(body: str) -> set[str]:
    return {h.rule_id for h in hits(body)}


def test_statements_respect_strings_comments_and_dollar_quotes() -> None:
    source = textwrap.dedent(
        """\
        -- one; two
        SELECT 'a;b'; /* c; */ SELECT "x;y";
        CREATE FUNCTION f() RETURNS int AS $body$ BEGIN RETURN 1; END; $body$ LANGUAGE plpgsql;
        SELECT 3
        """
    )
    found = statements(source)
    assert found is not None
    assert [(s.line, s.text.strip().split()[0]) for s in found] == [
        (2, "SELECT"),
        (2, "SELECT"),
        (3, "CREATE"),
        (4, "SELECT"),
    ]
    assert "RETURN 1; END;" in found[2].text


def test_grant_all() -> None:
    assert ids("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';") == {"sql.grant.all"}
    assert ids("grant all on all tables in schema public to app;") == {"sql.grant.all"}
    assert ids("GRANT ALL ON DATABASE shop TO app;") == {"sql.grant.all"}
    assert ids("GRANT ALL ON orders TO app;") == {"sql.grant.all"}
    assert ids("GRANT ALL ON SCHEMA public TO PUBLIC;") == {"sql.grant.all"}
    severities = {
        h.severity
        for h in hits("GRANT ALL PRIVILEGES ON *.* TO a;\nGRANT ALL ON DATABASE d TO a;\nGRANT ALL ON t TO a;")
    }
    assert severities == {None, "medium", "low"}


def test_grant_negatives() -> None:
    assert ids("GRANT SELECT, INSERT ON orders TO app;") == set()
    assert ids("-- GRANT ALL ON *.* TO root;\nSELECT 1;") == set()
    assert ids("SELECT 'GRANT ALL ON *.* TO x';") == set()
    assert ids("REVOKE ALL PRIVILEGES ON *.* FROM app;") == set()


def test_plaintext_credentials() -> None:
    assert ids("CREATE USER 'app'@'%' IDENTIFIED BY 'hunter2';") == {"sql.credentials.plaintext"}
    assert ids("CREATE ROLE app WITH LOGIN PASSWORD 'hunter2';") == {"sql.credentials.plaintext"}
    assert ids("ALTER USER app PASSWORD 'hunter2';") == {"sql.credentials.plaintext"}
    assert ids("SET PASSWORD FOR 'app'@'%' = 'hunter2';") == {"sql.credentials.plaintext"}
    assert ids("CREATE USER x IDENTIFIED WITH mysql_native_password BY 'hunter2';") == {"sql.credentials.plaintext"}
    assert ids("create user scott identified by tiger;") == set()  # an unquoted word is not read as a literal


def test_credential_negatives() -> None:
    assert ids("CREATE USER app IDENTIFIED BY PASSWORD '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';") == set()
    assert ids("CREATE ROLE app PASSWORD 'md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';") == set()
    assert ids("CREATE ROLE app PASSWORD 'SCRAM-SHA-256$4096:abc$def:ghi';") == set()
    assert ids("CREATE USER app IDENTIFIED BY '${DB_PASSWORD}';") == set()
    assert ids("CREATE USER app IDENTIFIED BY '<password>';") == set()
    assert ids("CREATE USER app IDENTIFIED BY '';") == set()
    assert ids("CREATE USER app IDENTIFIED BY '%s';") == set()
    assert ids("CREATE USER app IDENTIFIED WITH auth_socket;") == set()
    assert ids("INSERT INTO notes VALUES ('IDENTIFIED BY ''x''');") == set()
    assert ids("-- CREATE USER a IDENTIFIED BY 'secret';") == set()


def test_security_definer_without_search_path() -> None:
    source = """
        CREATE OR REPLACE FUNCTION admin.reset(uid int) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER AS $$
        BEGIN UPDATE users SET pw = NULL WHERE id = uid; END;
        $$;
    """
    assert ids(source) == {"sql.function.security_definer_path"}
    assert hits(source)[0].line == 2


def test_security_definer_negatives() -> None:
    fixed = """
        CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
        AS $$ SELECT 1 $$;
    """
    assert ids(fixed) == set()
    assert ids("CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;") == set()
    assert ids("CREATE FUNCTION f() RETURNS int SECURITY INVOKER LANGUAGE sql AS $$ SELECT 1 $$;") == set()
    mysql = "CREATE DEFINER=`root`@`localhost` PROCEDURE p() SQL SECURITY DEFINER BEGIN SELECT 1; END;"
    assert ids(mysql) == set()
    assert (
        ids(
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN PERFORM set_config('search_path', '', true); END $$;"
        )
        == set()
    )


def test_pathological_inputs_are_bounded() -> None:
    started = time.perf_counter()
    for unit in ("'\n", "/*\n", "$$\n", "$a$\n", "-- x\n", '"\n', "`\n", "\\\n", "$1\n"):
        assert isinstance(check_sql(unit * 150_000, "a.sql"), list), unit
    assert check_sql("SELECT 1;\n" * (MAX_STATEMENTS + 10), "a.sql") == "too_complex"
    assert check_sql("x" * 100_000, "a.sql") == "minified"
    assert time.perf_counter() - started < 20


def test_sql_files_are_scanned_with_suppression(tmp_path: Path) -> None:
    source = "GRANT ALL ON *.* TO a;\n-- kestrix: ignore[sql.grant.all] bootstrap script for a throwaway container\nGRANT ALL ON *.* TO b;\n"
    path = tmp_path / "init.sql"
    path.write_text(source)
    findings, _, suppressed, skip = scan_text(source, Candidate(path, "init.sql"))
    assert [(f.rule_id, f.line) for f in findings] == [("sql.grant.all", 1)] and suppressed == 1 and skip is None
