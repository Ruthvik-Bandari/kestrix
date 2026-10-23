# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Sources, filters, de-duplication and the project-disjoint split, on a synthetic CVEfixes database and mined commits."""

import gzip
import json
import sqlite3
from collections import Counter
from pathlib import Path

import pytest

from kestrixcodebench.build import build, merge_pairs, split_rows
from kestrixcodebench.common import CodeBenchError, Layout, read_jsonl
from kestrixcodebench.scan import locate, reduce_bandit, reduce_eslint, reduce_kestrix, scan_shard
from kestrixcodebench.sources import RawPair, repo_name

VULN = "import os\n\ndef run(x):\n    y = x.strip()\n    os.system('echo ' + y)\n    return y\n"
FIXED = "import os\n\ndef run(x):\n    y = x.strip()\n    os.system('echo ' + shlex(y))\n    return y\n"
JS_BEFORE = "function f(req, res) {\n  const a = 1;\n  const b = 2;\n  res.send(req.query.x);\n  return a + b;\n}\n"
JS_OTHER = "function g() {\n  return 1;\n}\nmodule.exports = g;\nvar z = 3;\n"
FILE_CHANGE = "INSERT INTO file_change VALUES (?,?,?,?,?,?,?,?,?,?)"


def code(n: int, fixed: bool = False) -> str:
    return (FIXED if fixed else VULN) + f"\n\ndef extra{n}():\n    return {n}\n"


def make_cvefixes(db_path: Path) -> None:
    db = sqlite3.connect(db_path)
    db.executescript(
        """
        CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT, score INTEGER);
        CREATE TABLE cve(cve_id TEXT, published_date TEXT, description TEXT);
        CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
        CREATE TABLE file_change(file_change_id TEXT, hash TEXT, old_path TEXT, new_path TEXT, filename TEXT,
          change_type TEXT, language TEXT, diff TEXT, code_before TEXT, code_after TEXT);
        """
    )
    for i in range(1, 41):
        sha, repo, cve = f"c{i:039d}", f"https://github.com/Org{i}/proj{i}", f"CVE-2020-{1000 + i}"
        db.execute("INSERT INTO fixes VALUES (?,?,?,0)", (cve, sha, repo))
        db.execute("INSERT INTO cve VALUES (?,?,?)", (cve, "2020-05-01T00:00:00", "d"))
        db.execute("INSERT INTO cwe_classification VALUES (?,?)", (cve, "CWE-78" if i % 2 else "NVD-CWE-Other"))
        rows = [
            ("ModificationType.MODIFY", f"src/mod{i}.py", code(i), code(i, True)),
            ("ModificationType.MODIFY", f"tests/test_{i}.py", code(i), code(i, True)),  # a test file: filtered
            ("ModificationType.ADD", f"src/new{i}.py", None, code(i)),  # no before version
        ]
        for n, (kind, path, before, after) in enumerate(rows):
            db.execute(FILE_CHANGE, (f"{i}-{n}", sha, path, path, path, kind, "python", "", before, after))
    # the same fix text in a fork: must merge into the first pair, not become a second one
    db.execute("INSERT INTO fixes VALUES (?,?,?,0)", ("CVE-2020-9999", "f" * 40, "https://github.com/Fork/proj1"))
    db.execute("INSERT INTO cwe_classification VALUES (?,?)", ("CVE-2020-9999", "CWE-77"))
    row = ("f", "f" * 40, "src/mod1.py", "src/mod1.py", "mod1.py", "ModificationType.MODIFY", "python", "")
    db.execute(FILE_CHANGE, (*row, code(1), code(1, True)))
    db.commit()
    db.close()


def make_mined(vul: Path) -> None:
    (vul / "work").mkdir(parents=True)
    (vul / "mine" / "commits").mkdir(parents=True)
    adv = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2021-1"],
        "cwes": ["CWE-79"],
        "published": "2021-01-01T00:00:00Z",
    }
    (vul / "work" / "ghsa.jsonl").write_text(json.dumps(adv) + "\n")
    targets = [
        {"advisories": [adv["id"]], "repo": "js/lib", "role": "ghsa", "sha": "a" * 40},
        {"advisories": [], "repo": "o/pooled", "role": "pool", "sha": "b" * 40},
    ]
    (vul / "work" / "mine_targets.jsonl").write_text("".join(json.dumps(t) + "\n" for t in targets))
    fixed = JS_BEFORE.replace("req.query.x", "esc(req.query.x)")
    commits = {
        "a" * 40: {
            "files": [{"path": "lib/f.js", "status": "M", "before": JS_BEFORE, "after": fixed, "unreadable": False}],
            "sampled": [{"path": "lib/other.js", "text": JS_OTHER}],
        },
        "b" * 40: {"files": [], "sampled": [{"path": "pool/p.py", "text": VULN + "\nprint(1)\n"}]},
    }
    for sha, record in commits.items():
        with gzip.open(vul / "mine" / "commits" / f"{sha}.json.gz", "wt") as fh:
            json.dump(record, fh)


def test_build_filters_merges_and_splits(tmp_path):
    db_path, vul = tmp_path / "cvefixes.sqlite", tmp_path / "vul"
    make_cvefixes(db_path)
    make_mined(vul)
    layout = Layout(tmp_path / "cb")
    body = build(layout, db_path, vul)
    pairs = list(read_jsonl(layout.pairs))
    assert len(pairs) == 41  # 40 python pairs (fork merged) plus 1 js pair; tests and added files dropped
    assert body["dropped"]["cvefixes:test"] == 40 and body["dropped"]["cvefixes:duplicate_pair"] == 1
    merged = next(p for p in pairs if p["repos"] == ["fork/proj1", "org1/proj1"])
    assert merged["cves"] == ["CVE-2020-1001", "CVE-2020-9999"] and merged["cwes"] == [77, 78]
    assert merged["families"] == ["cmdi"]
    js = next(p for p in pairs if p["language"] == "javascript")
    assert js["source"] == "ghsa" and js["families"] == ["xss"] and js["old_ranges"]
    assert {r["split"] for r in pairs} == {"dev", "test"}
    assert body["splits"]["dev"]["pairs"] + body["splits"]["test"]["pairs"] == 41
    assert body["evaluated"] == {"dev": True, "test": False}
    assert len(list(read_jsonl(layout.unchanged))) == 2
    for row in pairs:
        directory = layout.shard_dir(row["split"], int(row["id"][:6], 16) % 8)
        assert (directory / "b" / f"{row['id']}{row['ext']}").is_file()
        assert (directory / "a" / f"{row['id']}{row['ext']}").is_file()
        assert ((directory / "b").stat().st_mode & 0o077) == 0  # private


def test_split_never_straddles_a_repository_or_cve():
    def raw(i: int, repo: str, cve: str, before: str, after: str) -> RawPair:
        return RawPair("cvefixes", [repo], f"{i:040d}", "", [cve], [], [78], f"src/f{i}.py", before, after)

    body = "def f():\n    a = 1\n    b = 2\n    c = 3\n    return a\n"
    pairs = [
        raw(1, "o/a", "CVE-1", body, body + "x = 1\n"),
        raw(2, "o/b", "CVE-1", body + "# other\n", body + "x = 2\n"),  # same CVE as o/a
        raw(3, "o/c", "CVE-3", body, body + "x = 3\n"),  # same before-file text as o/a (a fork or copy)
        *[raw(10 + i, f"p/r{i}", f"CVE-{100 + i}", body + f"# {i}\n", body + f"# {i}\nz = 1\n") for i in range(40)],
    ]
    rows = merge_pairs(pairs, Counter())
    split, _ = split_rows(rows, [])
    by_repo = {r["repos"][0]: split[r["id"]] for r in rows}
    assert by_repo["o/a"] == by_repo["o/b"] == by_repo["o/c"]
    assert set(split.values()) == {"dev", "test"}


def test_repo_name():
    assert repo_name("https://github.com/Django/Django.git") == "django/django"
    assert repo_name("o/N") == "o/n"


def test_locate():
    assert locate("b/0123.py") == ("b", "0123")
    assert locate("./u/ab.tsx") == ("u", "ab")
    assert locate("x/0123.py") is None and locate("b/c/d.py") is None


def test_report_reducers():
    found, failed = reduce_kestrix(
        {
            "findings": [{"rule_id": "py.os.system", "cwe": "CWE-78", "path": "b/ab.py", "line": 3, "end_line": 4}],
            "files_skipped": [{"path": "a/cd.py", "reason": "syntax_error"}],
        }
    )
    assert found == [{"k": "b", "i": "ab", "r": "py.os.system", "l": 3, "e": 4, "f": ["cmdi"]}] and failed == {"a": 1}
    result = {
        "filename": "./b/ab.py",
        "test_id": "B602",
        "issue_cwe": {"id": 78},
        "line_number": 5,
        "line_range": [5, 6],
    }
    found, failed = reduce_bandit(
        {"results": [result], "errors": [{"filename": "./u/ef.py", "reason": "syntax error"}]}
    )
    assert found[0]["f"] == ["cmdi"] and found[0]["e"] == 6 and failed == {"u": 1}
    found, failed = reduce_eslint(
        [
            {"filePath": "/x/shard/b/ab.js", "messages": [{"ruleId": "security/detect-child-process", "line": 2}]},
            {"filePath": "/x/shard/a/cd.js", "messages": [{"ruleId": None, "fatal": True, "message": "Parsing error"}]},
            {"filePath": "/x/shard/u/ef.ts", "messages": [{"ruleId": "@typescript-eslint/no-explicit-any", "line": 1}]},
        ],
        Path("/x/shard"),
    )
    assert found[0]["f"] == ["cmdi"] and failed == {"a": 1}


def test_scan_refuses_the_test_split(tmp_path):
    with pytest.raises(CodeBenchError, match="locked test"):
        scan_shard(Layout(tmp_path), "kestrix", "test", 0, run="r", code_sha="sha")


def test_scan_runs_kestrix_on_a_shard(tmp_path):
    layout = Layout(tmp_path)
    shard = layout.shard_dir("dev", 0)
    for kind in ("b", "a", "u"):
        (shard / kind).mkdir(parents=True)
    (shard / "b" / "aa11.py").write_text(VULN)
    (shard / "a" / "aa11.py").write_text("x = 1\n")
    (shard / "u" / "bb22.py").write_text("y = 2\n")
    out = scan_shard(layout, "kestrix", "dev", 0, run="t", code_sha="sha")
    rows = list(read_jsonl(out))
    assert [(r["k"], r["i"], r["r"]) for r in rows] == [("b", "aa11", "py.os.system")]
    report = json.loads(layout.scan_report("t", "kestrix", 0).read_text())
    assert report["files"] == {"b": 1, "a": 1, "u": 1} and report["findings"] == 1


def test_web_files_are_a_language_and_only_language_keeps_one(tmp_path):
    from kestrixcodebench.build import language_of, pair_reason

    assert [language_of(f"a{ext}") for ext in (".vue", ".svelte", ".html", ".htm", ".css", ".scss")] == [
        ("web", ".vue"),
        ("web", ".svelte"),
        ("web", ".html"),
        ("web", ".htm"),
        ("web", ".css"),
        ("web", ".scss"),
    ]
    before = "<p>\n<div v-html='a'></div>\n<b>\n<i>\n<u>\n</p>\n"
    after = before.replace("v-html='a'", "")
    pair = RawPair("cvefixes", ["o/r"], "c" * 40, "", ["CVE-2020-1"], [], [79], "src/a.vue", before, after)
    assert pair_reason(pair) is None
    assert pair_reason(pair, "web") is None
    assert pair_reason(pair, "python") == "other_language"
    py = RawPair("cvefixes", ["o/r"], "c" * 40, "", ["CVE-2020-1"], [], [79], "src/a.py", VULN, FIXED)
    assert pair_reason(py, "web") == "other_language"


def test_scan_counts_web_files_for_kestrix_only():
    from kestrixcodebench.scan import count_files

    # only the file-name filter is exercised: an empty directory gives zero for every kind
    assert count_files(Path("/nonexistent"), "kestrix") == {"b": 0, "a": 0, "u": 0}


def test_web_corpus_counts_findings_per_rule(tmp_path):
    from kestrixcodebench.corpus import web_corpus

    tree = tmp_path / "pkg" / "node_modules" / "lib"
    tree.mkdir(parents=True)
    (tree / "a.html").write_text('<button onclick="go()">x</button>\n<p>fine</p>\n')
    (tree / "b.css").write_text(".a { color: red; }\n")
    (tree / "c.py").write_text("x = 1\n")
    layout = Layout(tmp_path / "root")
    report = json.loads(web_corpus(layout, [tmp_path / "pkg"], "t").read_text())
    assert report["files_scanned"] == {".css": 1, ".html": 1}
    assert report["rules"]["html.inline.event_handler"]["findings"] == 1
    assert report["all_rules_per_kloc"] == pytest.approx(1 / 0.005, rel=0.01)


def test_rule_rates_counts_every_rule_even_without_a_family(tmp_path):
    from kestrixcodebench.common import SHARDS, write_json, write_jsonl
    from kestrixcodebench.rates import rule_rates

    layout = Layout(tmp_path)
    pair = {
        "id": "p1",
        "split": "dev",
        "language": "web",
        "repos": ["o/r"],
        "commits": ["c"],
        "families": ["xss"],
        "after_lines": 100,
        "before_lines": 100,
        "ops": [[4, 5, 4, 5]],
        "old_ranges": [[5, 5]],
    }
    unchanged = {"id": "u1", "split": "dev", "language": "web", "repo": "o/r", "lines": 100}
    write_jsonl(layout.pairs, [pair])
    write_jsonl(layout.unchanged, [unchanged])
    rows = {
        0: [
            {"k": "b", "i": "p1", "r": "html.form.http_action", "l": 5, "e": 5, "f": []},
            {"k": "b", "i": "p1", "r": "html.form.http_action", "l": 90, "e": 90, "f": []},
            {"k": "a", "i": "p1", "r": "html.form.http_action", "l": 90, "e": 90, "f": []},
            {"k": "u", "i": "u1", "r": "css.import.http", "l": 1, "e": 1, "f": []},
        ]
    }
    for shard in range(SHARDS):
        write_jsonl(layout.findings_file("r", "kestrix", shard), rows.get(shard, []))
    write_json(layout.reports / "x.json", {})
    out = json.loads(rule_rates(layout, "r", "dev", "t").read_text())
    by_rule = {r["rule"]: r for r in out["rules"]}
    form = by_rule["html.form.http_action"]
    assert (form["before_any"], form["before_near_change"], form["after"], form["unchanged"]) == (2, 1, 1, 0)
    assert (form["detected_pairs"], form["after_alerts"]) == (0, 0)  # no family on these findings: lint-level
    assert by_rule["css.import.http"]["unchanged"] == 1
    assert form["clean_alerts_per_kloc"] == pytest.approx(1 / 0.2)
