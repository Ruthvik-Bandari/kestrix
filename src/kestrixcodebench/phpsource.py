# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A working database of the PHP (Phase 2), the Go, Java, Kotlin, C# and Ruby (Phase 4) or the C, C++, Rust and Swift
(Phase 5) files of CVEfixes fix commits.

``kestrixvul``'s working database keeps only Python, JavaScript and TypeScript file changes (the languages of that
project), so the PHP and the Phase 4 benchmarks stream the same pinned CVEfixes v1.0.8 archive (CC BY 4.0) once more and
keep the files with one of the wanted language labels (and nothing else of the file changes). CVEfixes has no Kotlin or
ERB label, so Phase 4 also keeps files of any label whose path ends in ``.kt``, ``.kts`` or ``.erb``; Phase 5 keeps ``C``,
``C++``, ``Rust`` and ``Swift`` and any file ending in ``.rs`` or ``.swift``. The tables, the
loader and the statement reader are ``kestrixvul.dump``'s; only the language filter differs. The output has the layout
``read_cvefixes`` reads, so ``build --only-language php`` (or ``p4``, ``p5``) uses it unchanged. The database is data on
the cluster, never committed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from kestrixvul.dump import WANTED, Getter, Loader, open_cvefixes, sqlite_rows

PHP_LABELS = frozenset({"PHP"})
P4_LABELS = frozenset({"Go", "Java", "C#", "Ruby"})
P4_SUFFIXES = (".kt", ".kts", ".erb")
P5_LABELS = frozenset({"C", "C++", "Rust", "Swift"})
P5_SUFFIXES = (".rs", ".swift")
LABEL_SETS: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "php": (PHP_LABELS, ()),
    "p4": (P4_LABELS, P4_SUFFIXES),
    "p5": (P5_LABELS, P5_SUFFIXES),
}


class PhpLoader(Loader):
    """Keeps fixes, CVEs and CWEs as ``Loader`` does, but file changes only of the wanted languages, and no method changes.

    ``labels``: CVEfixes language labels to keep; ``suffixes``: also keep a file of any label whose path ends so."""

    def __init__(
        self, db: sqlite3.Connection, labels: frozenset[str] = PHP_LABELS, suffixes: tuple[str, ...] = ()
    ) -> None:
        super().__init__(db)
        self.labels = labels
        self.suffixes = suffixes

    def _row_file_change(self, get: Getter) -> None:
        language = get("programming_language") or "None"
        self.files_by_language[language] += 1
        path = (get("new_path") or get("old_path") or get("filename") or "").lower()
        if language not in self.labels and not (self.suffixes and path.endswith(self.suffixes)):
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
                language.lower(),
                clean("diff"),
                clean("code_before"),
                clean("code_after"),
            ),
        )

    def _row_method_change(self, get: Getter) -> None:
        return


def load_php(zip_path: Path, out: Path, label_set: str = "php") -> dict[str, int]:
    """Stream the CVEfixes archive into a fresh working database at ``out`` with only the files of ``label_set``
    (``php``, ``p4`` or ``p5``); return the row counts."""
    tmp = out.with_name(out.name + ".tmp")
    tmp.unlink(missing_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(tmp)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    loader = PhpLoader(db, *LABEL_SETS[label_set])
    with open_cvefixes(zip_path) as stream:
        for table, get in sqlite_rows(stream, set(WANTED)):
            loader.row(table, get)
    loader.finish()
    db.close()
    tmp.chmod(0o600)
    tmp.replace(out)
    return dict(loader.rows)
