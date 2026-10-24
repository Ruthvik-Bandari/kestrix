# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import sqlite3
from pathlib import Path

from kestrixvul.dump import INDEXES, SCHEMA
from kestrixvul.labels import (
    Change,
    FileUnits,
    LineMap,
    Method,
    file_changes,
    label_commit,
    mentions_file,
    mentions_function,
    repo_key,
    run,
)

BEFORE = """import os


def run(cmd):
    cmd = cmd.strip()
    return os.system(cmd)


def helper(x):
    y = x + 1
    return y
"""
AFTER = """import os
import subprocess


def run(cmd):
    cmd = cmd.strip()
    check(cmd)
    return subprocess.run([cmd], check=True)


def helper(x):
    y = x + 1
    return y
"""
DIFF = (
    "@@ -1,6 +1,8 @@\n import os\n+import subprocess\n \n \n def run(cmd):\n     cmd = cmd.strip()\n"
    "-    return os.system(cmd)\n+    check(cmd)\n+    return subprocess.run([cmd], check=True)\n"
)


def test_line_map_follows_hunks_and_offsets():
    lines = LineMap(DIFF)
    assert lines.new_to_old(1) == 1
    assert lines.new_to_old(2) is None  # added
    assert lines.new_to_old(5) == 4  # def run
    assert lines.new_to_old(11) == 9  # def helper, after the hunk: shift of -2
    assert lines.old_to_new(6) is None  # deleted
    assert lines.old_to_new(9) == 11


def test_pairs_rows_and_recovers_a_missing_before_version_from_the_diff():
    after = [Method("run", 5, 8, "def run(cmd):\n    ...")]
    changes = file_changes([], after, DIFF, BEFORE, AFTER)
    assert len(changes) == 1
    assert changes[0].kind == "before_reconstructed"
    assert changes[0].before == "def run(cmd):\n    cmd = cmd.strip()\n    return os.system(cmd)"
    paired = file_changes([Method("run", 4, 6, "def run(cmd): ...")], after, DIFF, BEFORE, AFTER)
    assert [c.kind for c in paired] == ["paired"]


def test_a_function_the_fix_added_or_deleted_has_one_side_only():
    added = file_changes([], [Method("new", 2, 2, "import subprocess")], DIFF, BEFORE, AFTER)
    assert added[0].kind == "added" and added[0].before is None
    deleted = file_changes([Method("gone", 6, 6, "    return os.system(cmd)")], [], DIFF, BEFORE, AFTER)
    assert deleted[0].kind == "deleted" and deleted[0].after is None


def _file(path: str, *names: str, reason: str | None = None) -> FileUnits:
    return FileUnits(path, "python", reason, [Change(n, f"def {n}():\n  pass\n  pass", None, "paired") for n in names])


def test_onefunc_counts_other_languages_but_not_test_files():
    only = list(label_commit([_file("app/views.py", "show"), _file("tests/test_views.py", "t", reason="test")], 0, []))
    assert [label for *_, label in only] == ["onefunc"]
    with_c = list(label_commit([_file("app/views.py", "show")], 1, []))
    assert [label for *_, label in with_c] == ["uncertain"]


def test_nvdcheck_by_function_name_or_by_file_with_a_single_change():
    desc = ["The render_page function in app/views.py allows XSS."]
    labels = {c.name: label for _, c, label in label_commit([_file("app/views.py", "render_page", "other")], 0, desc)}
    assert labels == {"render_page": "nvd_name", "other": "uncertain"}
    by_file = list(label_commit([_file("app/views.py", "a"), _file("app/util.py", "b")], 0, desc))
    assert {c.name: label for _, c, label in by_file} == {"a": "nvd_file", "b": "uncertain"}


def test_plain_english_names_need_a_code_context():
    assert not mentions_function("Attackers can parse arbitrary input.", "parse")
    assert mentions_function("A flaw in the parse() method allows injection.", "parse")
    assert mentions_function("The `render` helper lacks escaping.", "Template.render")
    assert mentions_function("sanitizeUrl does not strip javascript: URLs.", "sanitizeUrl")
    assert not mentions_function("Reading data is unsafe.", "readData")
    assert not mentions_function("Short names like io are ignored.", "io")


def test_file_mentions_match_whole_file_names():
    assert mentions_file("A bug in lib/url.js allows bypass.", "src/lib/url.js")
    assert not mentions_file("A bug in myurl.js allows bypass.", "src/url.js")


def test_repo_key_normalizes_urls():
    assert repo_key("https://github.com/Django/Django.git/") == "github.com/django/django"
    assert repo_key("github.com/o/p/commit/abc") == "github.com/o/p"


def _work_db(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.execute("INSERT INTO fixes VALUES ('CVE-2025-0001', 'c1', 'https://github.com/o/p', NULL)")
    db.execute("INSERT INTO cve VALUES ('CVE-2025-0001', '2025-02-01T10:00Z', 'Command injection in run.')")
    db.execute("INSERT INTO cwe_classification VALUES ('CVE-2025-0001', 'CWE-78')")
    db.execute(
        "INSERT INTO file_change VALUES ('f1', 'c1', 'app.py', 'app.py', 'app.py', 'MODIFY', 'python', ?, ?, ?)",
        (DIFF, BEFORE, AFTER),
    )
    db.execute("INSERT INTO method_change VALUES ('f1', 'run', 'run(cmd)', 4, 6, ?, 1)", (BEFORE.split("\n\n\n")[1],))
    db.execute("INSERT INTO method_change VALUES ('f1', 'run', 'run(cmd)', 5, 8, ?, 0)", ("def run(cmd): ...",))
    db.executescript(INDEXES)
    db.commit()
    db.close()


def test_run_writes_onefunc_candidates_with_metadata(tmp_path: Path):
    (tmp_path / "work").mkdir()
    (tmp_path / "raw" / "sven" / "data_train_val" / "val").mkdir(parents=True)
    sven = {
        "func_name": "load",
        "func_src_before": "def load(p):\n    x = 1\n    return open(p)",
        "func_src_after": "def load(p):\n    x = 1\n    return open(safe(p))",
        "commit_link": "github.com/a/b/commit/" + "0" * 40,
        "file_name": "b/io.py",
        "vul_type": "cwe-022",
    }
    (tmp_path / "raw" / "sven" / "data_train_val" / "val" / "cwe-022.jsonl").write_text(json.dumps(sven) + "\n")
    _work_db(tmp_path / "work" / "cvefixes.sqlite")
    _work_db(tmp_path / "work" / "morefixes.sqlite")
    report = run(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "work" / "candidates.jsonl").read_text().splitlines()]
    cve = next(r for r in rows if r["source"] == "cvefixes")
    assert cve["label_rule"] == "onefunc" and cve["published"] == "2025-02-01"
    assert cve["cwes"] == ["CWE-78"] and cve["repo"] == "github.com/o/p"
    assert cve["vulnerable"].startswith("def run(cmd):")
    assert any(r["source"] == "sven" and r["sven_split"] == "val" for r in rows)
    # MoreFixes needs a fix score at or above the threshold, so the unscored fixture yields nothing.
    assert "morefixes/python" not in report["candidates"]


def test_a_corrupt_end_line_is_clamped_to_the_file():
    after = [Method("run", 5, 10**9, "def run(cmd): ...")]
    changes = file_changes([], after, DIFF, BEFORE, AFTER)
    assert changes[0].kind == "before_reconstructed"
    assert changes[0].before is not None and changes[0].before.startswith("def run(cmd):")
