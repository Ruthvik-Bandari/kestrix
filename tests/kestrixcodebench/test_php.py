# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The PHP benchmark pieces: the CVEfixes PHP loader, the language filter, the CWE-98 family and the Psalm reader."""

import sqlite3
from collections.abc import Callable
from pathlib import Path

from kestrixcodebench.build import language_of, pair_reason
from kestrixcodebench.common import PHP_EXTENSIONS
from kestrixcodebench.families import families_for_cwes, kestrix_families, psalm_families
from kestrixcodebench.phpsource import PhpLoader
from kestrixcodebench.scan import SCAN_TOOLS, count_files, reduce_psalm
from kestrixcodebench.sources import RawPair, read_cvefixes

BEFORE = "<?php\n$id = $_GET['id'];\n$r = mysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\necho $r;\n// end\n"
AFTER = BEFORE.replace('$id")', '" . (int)$id)')


def getter(row: dict[str, str | None]) -> Callable[[str], str | None]:
    return row.get


def test_php_loader_keeps_only_php_file_changes(tmp_path: Path) -> None:
    db = sqlite3.connect(tmp_path / "w.sqlite")
    loader = PhpLoader(db)
    base = {"hash": "h1", "old_path": "a.php", "new_path": "a.php", "filename": "a.php", "change_type": "MODIFY"}
    loader.row(
        "file_change",
        getter(
            {**base, "programming_language": "PHP", "file_change_id": "1", "code_before": BEFORE, "code_after": AFTER}
        ),
    )
    loader.row(
        "file_change",
        getter(
            {**base, "programming_language": "Python", "file_change_id": "2", "code_before": "x", "code_after": "y"}
        ),
    )
    loader.row("method_change", getter({"file_change_id": "1", "name": "f"}))
    loader.row(
        "fixes", getter({"cve_id": "CVE-2020-1234", "hash": "h1", "repo_url": "https://github.com/o/r", "score": "9"})
    )
    loader.row("cwe_classification", getter({"cve_id": "CVE-2020-1234", "cwe_id": "CWE-89"}))
    loader.row("cve", getter({"cve_id": "CVE-2020-1234", "published_date": "2020-05-01", "description": "d"}))
    loader.finish()
    assert db.execute("SELECT count(*) FROM file_change").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM method_change").fetchone()[0] == 0
    db.close()
    (pair,) = list(read_cvefixes(tmp_path / "w.sqlite"))
    assert (pair.path, pair.cwes, pair.repos) == ("a.php", [89], ["o/r"])


def test_php_is_a_language_and_the_default_build_leaves_it_out() -> None:
    assert [language_of(f"a{ext}") for ext in PHP_EXTENSIONS] == [("php", ".php"), ("php", ".phtml")]
    pair = RawPair("cvefixes", ["o/r"], "c" * 40, "", ["CVE-2020-1"], [], [89], "src/a.php", BEFORE, AFTER)
    assert pair_reason(pair, "php") is None
    assert pair_reason(pair, "python") == "other_language"
    assert pair_reason(pair) == "other_language"


def test_vendor_and_test_php_files_are_filtered() -> None:
    for path in ("vendor/x/a.php", "tests/AFeatureTest.php"):
        pair = RawPair("cvefixes", ["o/r"], "c" * 40, "", ["CVE-2020-1"], [], [89], path, BEFORE, AFTER)
        assert pair_reason(pair, "php") is not None, path


def test_cwe_98_is_the_file_inclusion_family_and_php_rules_map_by_cwe() -> None:
    assert families_for_cwes([98]) == {"fileinclusion"}
    assert kestrix_families("php.include.dynamic", "CWE-98") == {"fileinclusion"}
    assert kestrix_families("php.sql.injection", "CWE-89") == {"sqli"}
    assert kestrix_families("php.xss.echo", "CWE-79") == {"xss"}
    assert kestrix_families("sql.grant.all", "CWE-250") == frozenset()


def test_psalm_taint_types_map_to_families_and_parse_errors_are_counted() -> None:
    assert psalm_families("TaintedSql") == {"sqli"}
    assert psalm_families("TaintedHtml") == {"xss"}
    assert psalm_families("TaintedInclude") == {"fileinclusion"}
    assert psalm_families("TaintedHeader") == frozenset()
    issues = [
        {"type": "TaintedSql", "line_from": 3, "line_to": 4},
        {"type": "UndefinedVariable", "line_from": 9, "line_to": 9},
    ]
    records, bad = reduce_psalm(issues, "b/abc.php")
    assert bad == 0 and [(r["k"], r["i"], r["r"], r["l"], r["e"], r["f"]) for r in records] == [
        ("b", "abc", "TaintedSql", 3, 4, ["sqli"])
    ]
    assert reduce_psalm([{"type": "ParseError", "line_from": 1}], "a/x.php") == ([], 1)


def test_psalm_is_a_scan_tool_and_counts_php_files() -> None:
    assert "psalm" in SCAN_TOOLS
    assert count_files(Path("/nonexistent"), "psalm") == {"b": 0, "a": 0, "u": 0}
