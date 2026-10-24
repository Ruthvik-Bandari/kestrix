# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A working database of the PHP files of CVEfixes fix commits.

``kestrixvul``'s working database keeps only Python, JavaScript and TypeScript file changes (the languages of that
project), so the PHP benchmark streams the same pinned CVEfixes v1.0.8 archive (CC BY 4.0) once more and keeps the
files labelled ``PHP`` (and nothing else of the file changes). The tables, the loader and the statement reader are
``kestrixvul.dump``'s; only the language filter differs. The output has the layout ``read_cvefixes`` reads, so
``build --only-language php`` uses it unchanged. The database is data on the cluster, never committed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from kestrixvul.dump import WANTED, Getter, Loader, open_cvefixes, sqlite_rows

PHP_LABELS = frozenset({"PHP"})


class PhpLoader(Loader):
    """Keeps fixes, CVEs and CWEs as ``Loader`` does, but file changes only of PHP, and no method changes."""

    def _row_file_change(self, get: Getter) -> None:
        language = get("programming_language") or "None"
        self.files_by_language[language] += 1
        if language not in PHP_LABELS:
            return
        fc_id = get("file_change_id") or ""
        self.kept_files[fc_id] = language
        none = {"None", "nan", ""}

        def clean(column: str) -> str | None:
            value = get(column)
            return None if value is None or value in none else value

        self._add(
            "file_change",
            (
                fc_id,
                get("hash"),
                clean("old_path"),
                clean("new_path"),
                get("filename"),
                get("change_type"),
                "php",
                clean("diff"),
                clean("code_before"),
                clean("code_after"),
            ),
        )

    def _row_method_change(self, get: Getter) -> None:
        return


def load_php(zip_path: Path, out: Path) -> dict[str, int]:
    """Stream the CVEfixes archive into a fresh PHP-only working database at ``out``; return the row counts."""
    tmp = out.with_name(out.name + ".tmp")
    tmp.unlink(missing_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(tmp)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    loader = PhpLoader(db)
    with open_cvefixes(zip_path) as stream:
        for table, get in sqlite_rows(stream, set(WANTED)):
            loader.row(table, get)
    loader.finish()
    db.close()
    tmp.chmod(0o600)
    tmp.replace(out)
    return dict(loader.rows)
