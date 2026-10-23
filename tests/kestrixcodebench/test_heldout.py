# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""test2: advisory selection against the existing data, the build, the tuning split and the one-time evaluation."""

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from kestrixcodebench import heldout
from kestrixcodebench.build import build
from kestrixcodebench.common import SHARDS, CodeBenchError, Layout, read_jsonl
from kestrixcodebench.report import dev_report
from kestrixcodebench.scan import scan_shard

from .test_build import JS_BEFORE, VULN, make_cvefixes, make_mined

NEW_JS = JS_BEFORE.replace("const a = 1", "const a = 7")  # not a file the round-1 data holds
FIXED_JS = NEW_JS.replace("req.query.x", "esc(req.query.x)")
OLD_FIXED_JS = JS_BEFORE.replace("req.query.x", "esc(req.query.x)")
PY_FIXED = VULN.replace("os.system('echo ' + y)", "os.system('echo ' + shlex.quote(y))")


def advisory(
    root: Path, ghsa: str, aliases: list[str], urls: list[str], *, withdrawn: bool = False, eco: str = "npm"
) -> None:
    path = root / "raw" / "ghsa" / "advisories" / "github-reviewed" / "2026" / "10" / ghsa
    path.mkdir(parents=True)
    doc = {
        "id": ghsa,
        "aliases": aliases,
        "published": "2026-10-20T00:00:00Z",
        "affected": [{"package": {"ecosystem": eco, "name": "x"}}],
        "references": [{"type": "WEB", "url": u} for u in urls],
        "database_specific": {"cwe_ids": ["CWE-79"]},
    }
    if withdrawn:
        doc["withdrawn"] = "2026-10-21T00:00:00Z"
    (path / f"{ghsa}.json").write_text(json.dumps(doc))


def tables(tmp_path: Path) -> tuple[Path, Path]:
    """(round-1 benchmark root, kestrixvul root) with the data of make_cvefixes / make_mined (a repo, ids, commits)."""
    make_cvefixes(tmp_path / "vul-cvefixes.sqlite")
    vul = tmp_path / "vul"
    make_mined(vul)
    work = vul / "work"
    work.mkdir(exist_ok=True)
    (work / "cvefixes.sqlite").write_bytes((tmp_path / "vul-cvefixes.sqlite").read_bytes())
    morefixes = sqlite3.connect(work / "morefixes.sqlite")
    morefixes.execute("CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT, score INTEGER)")
    morefixes.execute("INSERT INTO fixes VALUES ('CVE-2019-5', ?, 'https://github.com/MoreOrg/more', 90)", ("d" * 40,))
    morefixes.commit()
    morefixes.close()
    old = tmp_path / "old"
    build(Layout(old), tmp_path / "vul-cvefixes.sqlite", vul)
    return old, vul


def selection(tmp_path: Path, *, allow_morefixes: bool = False, allow_known_repos: bool = False) -> tuple[Layout, dict]:
    old, vul = tables(tmp_path)
    root = tmp_path / "t2"
    new = "1" * 40
    advisory(root, "GHSA-new1-aaaa-aaaa", ["CVE-2026-1"], [f"https://github.com/Fresh/lib/commit/{new}"])
    advisory(root, "GHSA-new2-aaaa-aaaa", [], [f"https://github.com/Fresh2/lib2/pull/9/commits/{'2' * 40}"])
    advisory(root, "GHSA-aaaa-bbbb-cccc", ["CVE-2021-1"], [f"https://github.com/js/lib/commit/{'3' * 40}"])  # id known
    advisory(
        root, "GHSA-cve1-aaaa-aaaa", ["CVE-2020-1001"], [f"https://github.com/Other/x/commit/{'4' * 40}"]
    )  # CVE known
    advisory(
        root, "GHSA-cmt1-aaaa-aaaa", [], [f"https://github.com/Other2/x/commit/{'a' * 40}"]
    )  # commit known (mined)
    advisory(
        root, "GHSA-cmt2-aaaa-aaaa", ["CVE-2026-2"], [f"https://github.com/MoreOrg/more/commit/{'d' * 40}"]
    )  # MoreFixes
    advisory(root, "GHSA-repo-aaaa-aaaa", [], [f"https://github.com/Org7/proj7/commit/{'5' * 40}"])  # repository known
    advisory(root, "GHSA-abbr-aaaa-aaaa", [], ["https://github.com/Fresh3/lib3/commit/abc1234"])  # abbreviated sha
    advisory(root, "GHSA-wdrn-aaaa-aaaa", [], [f"https://github.com/Fresh4/l/commit/{'6' * 40}"], withdrawn=True)
    advisory(root, "GHSA-nocm-aaaa-aaaa", [], ["https://github.com/Fresh5/l/issues/3"])
    advisory(root, "GHSA-pypi-aaaa-aaaa", [], [f"https://github.com/Fresh6/py/commit/{'7' * 40}"], eco="PyPI")
    advisory(root, "GHSA-go-aaaa-aaaa", [], [f"https://github.com/Fresh7/go/commit/{'8' * 40}"], eco="Go")
    report = heldout.select_targets(
        root, old, vul, allow_morefixes=allow_morefixes, allow_known_repos=allow_known_repos
    )
    return Layout(root), report


def test_select_keeps_only_advisories_and_commits_not_in_the_existing_data(tmp_path):
    layout, report = selection(tmp_path)
    targets = list(read_jsonl(layout.work / "mine_targets.jsonl"))
    assert {t["sha"] for t in targets} == {"1" * 40, "2" * 40, "7" * 40}
    assert all(t["role"] == "ghsa" for t in targets)
    counts = report["counts"]
    assert counts["excluded_ghsa_id_in_existing"] == 1 and counts["excluded_cve_id_in_existing"] == 1
    assert counts["excluded_commit_in_existing"] == 1  # the mined commit
    assert counts["morefixes_only"] == 1 and counts["known_repository"] == 1  # held back, not excluded for good
    assert counts["skipped_abbreviated_sha"] == 1
    assert report["selected"]["advisories"] == 3 and report["selected"]["by_ecosystem"] == {"PyPI": 1, "npm": 2}
    kept = {a["id"] for a in read_jsonl(layout.work / "ghsa.jsonl")}
    assert kept == {"GHSA-new1-aaaa-aaaa", "GHSA-new2-aaaa-aaaa", "GHSA-pypi-aaaa-aaaa"}


def test_select_reports_what_each_relaxation_would_add(tmp_path):
    _, report = selection(tmp_path)
    tiers = {k: v["fix_commits"] for k, v in report["tiers"].items()}
    assert tiers == {
        "morefixes=excluded,repositories=new only": 3,
        "morefixes=excluded,repositories=allowed": 4,  # the commit of a repository round 1 scanned
        "morefixes=allowed,repositories=new only": 4,  # the MoreFixes-only commit
        "morefixes=allowed,repositories=allowed": 5,
    }


def test_select_can_take_morefixes_commits_and_known_repositories_when_asked(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    layout, report = selection(tmp_path / "a", allow_morefixes=True)
    assert {"d" * 40} <= {t["sha"] for t in read_jsonl(layout.work / "mine_targets.jsonl")}
    layout, report = selection(tmp_path / "b", allow_known_repos=True)
    assert "5" * 40 in {t["sha"] for t in read_jsonl(layout.work / "mine_targets.jsonl")}
    assert report["allow_known_repos"]


def mine(layout: Layout, sha: str, files: list[dict], sampled: list[dict]) -> None:
    path = layout.root / "mine" / "commits"
    path.mkdir(parents=True, exist_ok=True)
    with gzip.open(path / f"{sha}.json.gz", "wt") as fh:
        json.dump({"files": files, "sampled": sampled}, fh)


def test_build_writes_an_all_test_set_with_no_overlap_and_private_manifests(tmp_path):
    layout, _ = selection(tmp_path)
    old, vul = tmp_path / "old", tmp_path / "vul"
    js = {"path": "lib/f.js", "status": "M", "before": NEW_JS, "after": FIXED_JS, "unreadable": False}
    py = {
        "path": "pkg/m.py",
        "status": "M",
        "before": VULN + "\nX = 1\n",
        "after": PY_FIXED + "\nX = 1\n",
        "unreadable": False,
    }
    old_blob = {  # the before text of a round-1 pair (a fork or backport)
        "path": "lib/g.js",
        "status": "M",
        "before": JS_BEFORE,
        "after": OLD_FIXED_JS + "\n// x\n",
        "unreadable": False,
    }
    mine(
        layout,
        "1" * 40,
        [js, old_blob],
        [{"path": "lib/o.js", "text": "function g() {\n  return 1;\n}\nvar z = 3;\nvar y = 4;\n"}],
    )
    mine(layout, "7" * 40, [py], [])
    mine(layout, "2" * 40, [], [])
    body = heldout.build_heldout(layout, old, vul)
    test = body["splits"]["test"]
    assert "dev" not in body["splits"] and body["name"] == "test2" and body["evaluated"] == {"test": False}
    assert test["pairs"] == 2 and test["projects"] == 2 and test["unchanged_files"] == 1
    assert test["by_language"] == {"javascript": 1, "python": 1}
    assert body["overlap_with_existing"] == dict.fromkeys(
        ("ghsa_ids", "cve_ids", "fix_commits", "repositories", "file_contents", "morefixes_commits_allowed"), 0
    )
    pairs = list(read_jsonl(layout.pairs))
    assert {r["split"] for r in pairs} == {"test"} and {r["advisories"][0][:9] for r in pairs} == {
        "GHSA-new1",
        "GHSA-pypi",
    }
    private = json.loads((layout.reports / "test2-files.json").read_text())
    assert {r["id"] for r in private["pairs"]} == {r["id"] for r in pairs} and private["unchanged"][0]["text_sha"]
    assert (layout.reports / "test2-files.json").stat().st_mode & 0o077 == 0
    assert body["dropped"]["ghsa:overlap_content"] == 1  # the second file has the same before text as a round-1 pair


def test_build_refuses_targets_that_overlap_the_existing_data(tmp_path):
    layout, _ = selection(tmp_path)
    old, vul = tmp_path / "old", tmp_path / "vul"
    (layout.root / "work" / "mine_targets.jsonl").write_text(
        json.dumps({"advisories": ["GHSA-aaaa-bbbb-cccc"], "repo": "x/y", "role": "ghsa", "sha": "a" * 40}) + "\n"
    )
    mine(
        layout, "a" * 40, [{"path": "a.py", "status": "M", "before": VULN, "after": PY_FIXED, "unreadable": False}], []
    )
    with pytest.raises(CodeBenchError, match="overlaps the existing data"):
        heldout.build_heldout(layout, old, vul)


@pytest.fixture
def spent(tmp_path):
    make_cvefixes(tmp_path / "cvefixes.sqlite")
    make_mined(tmp_path / "vul")
    layout = Layout(tmp_path / "cb")
    build(layout, tmp_path / "cvefixes.sqlite", tmp_path / "vul")
    return layout


def test_tuning_split_needs_the_spent_lock_and_scans_dev_and_test(spent):
    with pytest.raises(CodeBenchError, match="not spent"):
        scan_shard(spent, "kestrix", "tuning", 0, run="t", code_sha="x")
    (spent.reports / "LOCKED_EVAL.json").write_text("{}")
    for shard in range(SHARDS):
        scan_shard(spent, "kestrix", "tuning", shard, run="t", code_sha="x")
    out = dev_report(spent, {"kestrix": "t"}, "t", reps=10, split="tuning")
    body = json.loads(out.read_text())
    assert body["split"] == "tuning" and "spent" in body["note"]
    total = sum(v["pairs"] for v in body["dev_data"].values())
    assert body["tools"]["kestrix"]["subsets"]["all"]["pairs"] == total
    report = json.loads(spent.scan_report("t", "kestrix", 0).read_text())
    assert report["split"] == "tuning"


def test_locked_test2_runs_once_with_two_kestrix_trees(tmp_path):
    layout, _ = selection(tmp_path)
    old, vul = tmp_path / "old", tmp_path / "vul"
    js = {"path": "lib/f.js", "status": "M", "before": NEW_JS, "after": FIXED_JS, "unreadable": False}
    py = {
        "path": "pkg/m.py",
        "status": "M",
        "before": VULN + "\nX = 1\n",
        "after": PY_FIXED + "\nX = 1\n",
        "unreadable": False,
    }
    mine(layout, "1" * 40, [js], [])
    mine(layout, "7" * 40, [py], [])
    mine(layout, "2" * 40, [], [])
    heldout.build_heldout(layout, old, vul)
    tree = Path(__file__).resolve().parents[2]  # this repository: packages/kestrix-scan/src is a kestrix tree
    out = heldout.locked_test2(layout, "unit", {"r1": tree}, "sha", reps=10, others=())
    body = json.loads(out.read_text())
    assert set(body["tools"]) == {"kestrix", "kestrix@r1"} and body["split"] == "test2"
    assert body["paired_final_vs_r1"]["all"]["detection"]["delta"] == 0.0
    claim = json.loads((layout.reports / heldout.LOCK_NAME).read_text())
    assert claim["report"] == out.name and claim["report_sha256"] and claim["kestrix_trees"] == {"r1": str(tree)}
    with pytest.raises(CodeBenchError, match="already ran"):
        heldout.locked_test2(layout, "again", {"r1": tree}, "sha", reps=10, others=())


def test_locked_test2_refuses_a_root_that_is_not_an_unevaluated_test2(tmp_path):
    layout = Layout(tmp_path / "cb")
    (layout.reports).mkdir(parents=True)
    layout.split_manifest.write_text(
        json.dumps({"name": "other", "evaluated": {"test": False}, "manifest_sha256": "x"})
    )
    with pytest.raises(CodeBenchError, match="unevaluated test2"):
        heldout.locked_test2(layout, "x", {}, "sha", reps=5, others=())


def test_select_published_after_keeps_only_newer_advisories(tmp_path):
    old, vul = tables(tmp_path)
    root = tmp_path / "t3"
    advisory(
        root, "GHSA-new1-aaaa-aaaa", [], [f"https://github.com/Fresh/lib/commit/{'1' * 40}"]
    )  # published 2026-10-20
    report = heldout.select_targets(root, old, vul, published_after="2026-10-19")
    assert report["selected"]["advisories"] == 1 and report["published_after"] == "2026-10-19"
    report = heldout.select_targets(root, old, vul, published_after="2026-10-20")
    assert report["selected"]["advisories"] == 0
    assert report["counts"]["excluded_published_on_or_before_cutoff"] == 1
