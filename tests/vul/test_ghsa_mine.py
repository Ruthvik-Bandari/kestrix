# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import gzip
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from kestrixvul.functions import diff_functions, js_functions, python_functions
from kestrixvul.ghsa_mine import (
    FetchConfig,
    Git,
    GitError,
    Limiter,
    Status,
    extract,
    extract_commit,
    fetch_commit,
    remote_url,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

APP_V1 = """import os


def run(cmd):
    cmd = cmd.strip()
    return os.system(cmd)


def helper(x):
    y = x + 1
    return y


class Store:
    def get(self, key):
        value = self.db[key]
        return value
"""
APP_V2 = APP_V1.replace("    return os.system(cmd)", "    check(cmd)\n    return subprocess.run([cmd], check=True)")
UTIL_JS = "function render(items) {\n  const out = [];\n  items.forEach(i => out.push(i));\n  return out;\n}\n"


def _git(cwd: Path, *args: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    out = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env | {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
    )
    return out.stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    (repo / "app").mkdir(parents=True)
    (repo / "tests").mkdir()
    _git(repo, "init", "-q")
    (repo / "app" / "views.py").write_text(APP_V1)
    (repo / "app" / "util.js").write_text(UTIL_JS)
    (repo / "tests" / "test_views.py").write_text("def test_run():\n    assert True\n    assert 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "v1")
    (repo / "app" / "views.py").write_text(APP_V2)
    (repo / "tests" / "test_views.py").write_text("def test_run():\n    assert True\n    assert 2\n")
    (repo / "native.c").write_text("int main(void) { return 0; }\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fix")
    _git(repo, "config", "uploadpack.allowFilter", "true")
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    return repo, _git(repo, "rev-parse", "HEAD")


def _fetch(tmp_path: Path, upstream: tuple[Path, str], **kw: object) -> dict:
    repo, sha = upstream
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    git = Git(tmp_path / "clone.git", tmp_path / "home", FetchConfig(**kw))  # type: ignore[arg-type]
    git.init(f"file://{repo}")
    return fetch_commit(git, Limiter(0.0), git.config, "o/p", sha)


def test_fetch_gets_only_the_changed_target_files_and_a_parent_sample(tmp_path: Path, upstream):
    record = _fetch(tmp_path, upstream)
    assert [f["path"] for f in record["files"]] == ["app/views.py"]
    assert record["files"][0]["before"] == APP_V1 and record["files"][0]["after"] == APP_V2
    assert record["excluded"] == [{"path": "tests/test_views.py", "reason": "test"}]
    assert record["other_code_changed"] == ["native.c"]
    assert [s["path"] for s in record["sampled"]] == ["app/util.js"]  # tests/ is filtered out


def test_fetch_enforces_the_size_cap(tmp_path: Path, upstream):
    with pytest.raises(GitError) as err:
        _fetch(tmp_path, upstream, max_bytes=10)
    assert err.value.status == "too_large"


def test_remote_url_is_anonymous_https_and_validated():
    assert remote_url("pallets/markupsafe") == "https://github.com/pallets/markupsafe.git"
    with pytest.raises(GitError):
        remote_url("evil/../x;rm")


def test_extract_labels_onefunc_and_keeps_unchanged_functions_as_negatives(tmp_path: Path, upstream):
    record = _fetch(tmp_path, upstream)
    record["other_code_changed"] = []  # without the C file the fix changes one function
    meta = {"GHSA-x": {"id": "GHSA-x", "aliases": ["CVE-2025-1"], "cwes": ["CWE-78"], "summary": "Command injection",
                       "details": "", "cve_descriptions": [], "published": "2025-01-02"}}  # fmt: skip
    stats: Counter[str] = Counter()
    target = {"repo": "o/p", "sha": record["sha"], "role": "ghsa", "advisories": ["GHSA-x"]}
    candidates, negatives = extract_commit(record, target, meta, stats)
    assert [(c["function"], c["label_rule"], c["pair_kind"]) for c in candidates] == [("run", "onefunc", "paired")]
    assert candidates[0]["advisory_ids"] == ["CVE-2025-1", "GHSA-x"] and candidates[0]["published"] == "2025-01-02"
    assert {(n["function"], n["origin"]) for n in negatives} == {
        ("helper", "changed_file"),
        ("Store.get", "changed_file"),
        ("render", "parent_snapshot"),
    }
    assert all(n["label"] == "negative_unchanged" for n in negatives)
    with_c = extract_commit(_fetch(tmp_path / "again", upstream), target, meta, Counter())[0]
    assert with_c == []  # a changed C file counts as another changed function: OneFunc does not fire


def test_extract_resumes_from_written_commit_files(tmp_path: Path, upstream):
    record = _fetch(tmp_path, upstream)
    (tmp_path / "work").mkdir()
    (tmp_path / "mine" / "commits").mkdir(parents=True)
    with gzip.open(tmp_path / "mine" / "commits" / f"{record['sha']}.json.gz", "wt") as fh:
        json.dump(record, fh)
    target = {"repo": "o/p", "sha": record["sha"], "role": "pool", "advisories": []}
    (tmp_path / "work" / "mine_targets.jsonl").write_text(json.dumps(target) + "\n")
    status = Status(tmp_path / "mine" / "status.jsonl")
    status.record("o/p", record["sha"], "fetched")
    assert Status(tmp_path / "mine" / "status.jsonl").final(record["sha"])
    report = extract(tmp_path)
    assert report["counts"]["commits"] == 1
    rows = (tmp_path / "work" / "negative_candidates.jsonl").read_text().splitlines()
    assert len(rows) == 3 and (tmp_path / "work" / "ghsa_candidates.jsonl").read_text() == ""


def test_transient_status_is_retried_on_resume(tmp_path: Path):
    status = Status(tmp_path / "status.jsonl")
    status.record("o/p", "a" * 40, "transient", "RPC failed")
    assert not Status(tmp_path / "status.jsonl").final("a" * 40)
    status.record("o/p", "a" * 40, "unavailable", "Repository not found")
    assert Status(tmp_path / "status.jsonl").final("a" * 40)


def test_python_units_skip_nested_functions_and_name_methods():
    names = [
        f.name
        for f in python_functions(APP_V1 + "\n\ndef outer():\n    def inner():\n        pass\n    return inner\n")
    ]
    assert names == ["run", "helper", "Store.get", "outer"]


def test_python2_files_fall_back_to_indentation():
    funcs = python_functions("def f(x):\n    print x\n    return 1\n\nclass K:\n    def m(self):\n        print 'a'\n")
    assert [(f.name, f.start, f.end) for f in funcs] == [("f", 1, 3), ("K.m", 6, 7)]


def test_js_units_methods_arrows_and_shadow_callbacks():
    code = (
        "class Foo {\n  get(id) {\n    return db.find(id, function (e) { cb(e); });\n  }\n}\n"
        "exports.handler = async (req, res) => {\n  res.send(req.query.q);\n};\n"
        "app.get('/x', function (req, res) {\n  res.send(1);\n});\n"
        "define(function () {\n  function inner() { const re = /}/; return re; }\n});\n"
    )
    funcs = js_functions(code, "javascript", "a.js")
    assert funcs is not None
    assert [(f.name, f.start, f.shadow) for f in funcs] == [
        ("Foo.get", 2, False),
        ("handler", 6, False),
        ("(anonymous)", 9, True),
        ("inner", 13, False),
    ]


def test_diff_pairs_by_name_and_counts_changed_shadow_units():
    before = js_functions("function a() { return 1; }\nx(function () { return 1; });\n", "javascript")
    after = js_functions(
        "function a() { return 2; }\nx(function () { return 2; });\nfunction b() { return 3; }\n", "javascript"
    )
    assert before is not None and after is not None
    diff = diff_functions(before, after)
    assert [(c.name, c.kind) for c in diff.changes] == [("a", "paired"), ("b", "added")]
    assert diff.shadow_changed == 1 and diff.unchanged == []
