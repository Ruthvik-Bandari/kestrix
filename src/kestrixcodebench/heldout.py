# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``test2``: a second held-out file-pair set from a fresh GitHub Advisory Database checkout (CC BY 4.0).

Round 1 spent its locked test (``LOCKED_EVAL.json``); round 2 needs data no rule was tuned on. Three stages:

1. ``select`` (offline, Slurm): reviewed PyPI and npm advisories of the fresh checkout whose references hold a GitHub
   fix commit (``/commit/<sha>`` or ``/pull/<n>/commits/<sha>``) and that are **not in the existing data**: no GHSA or
   CVE id, no fix commit (CVEfixes, MoreFixes, the mined advisory commits, round-1 pairs and unchanged files) and, by
   default, no repository of it. The advisory records and the commits to fetch go to ``work/ghsa.jsonl`` and
   ``work/mine_targets.jsonl`` under the new root, the format ``kestrixvul.ghsa_mine`` and ``sources.read_ghsa`` read.
2. ``fetch`` (transfer node): ``kestrixvul.ghsa_mine.fetch`` with at most ``MAX_CHANGED_FILES`` changed files per commit.
3. ``build`` (offline): the round-1 filters, de-duplication and shards, every pair in the ``test`` split of the new root;
   a manifest (advisory ids, repository, commit, SHA-256 of the files) stays private on the cluster, the aggregate
   goes to the repository. No file is scanned here; the one-time evaluation is ``locked-test2``.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kestrixvul.ghsa_mine import REPO, SHA, FetchConfig, fetch

from .common import (
    KINDS,
    SHARDS,
    CodeBenchError,
    Layout,
    ids_sha256,
    now,
    private_dir,
    read_jsonl,
    write_json,
    write_jsonl,
)

MAX_CHANGED_FILES = 3
MAX_ADVISORY_BYTES = 1024 * 1024
COMMIT_URL = re.compile(
    r"https?://github\.com/([\w.-]+)/([\w.-]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})(?![0-9a-f])", re.IGNORECASE
)
SPLIT = "test"
LOCK_NAME = "LOCKED_EVAL_TEST2.json"


def repo_of(name: str) -> str:
    return name.strip().lower().removesuffix(".git")


def _repo_from_url(url: str) -> str:
    stripped = re.sub(r"^https?://(www\.)?github\.com/", "", url.strip().rstrip("/")).removesuffix(".git")
    return "/".join(stripped.split("/")[:2]).lower()


class Existing:
    """What round 1 touched. ``core``: the benchmark's own pairs and unchanged files, kestrixvul's mined targets (every
    role, fetched or not) and CVEfixes (the benchmark's other source): advisory ids, CVE ids, fix commits, repositories
    and file contents. ``more_*``: MoreFixes rows, which this benchmark does not use (reported, and allowed on request)."""

    def __init__(self) -> None:
        self.advisories: set[str] = set()
        self.cves: set[str] = set()
        self.commits: set[str] = set()
        self.repos: set[str] = set()
        self.before_shas: set[str] = set()
        self.more_commits: set[str] = set()
        self.more_cves: set[str] = set()
        self.sources: Counter[str] = Counter()

    _SETS = ("advisories", "cves", "commits", "repos", "before_shas", "more_commits", "more_cves")

    def dump(self) -> dict[str, Any]:
        return {name: sorted(getattr(self, name)) for name in self._SETS} | {"sources": dict(self.sources)}

    @classmethod
    def load(cls, data: dict[str, Any]) -> Existing:
        old = cls()
        for name in cls._SETS:
            setattr(old, name, set(data[name]))
        old.sources = Counter(data["sources"])
        return old


def load_existing(codebench: Path, vul: Path, cache: Path | None = None) -> Existing:
    """The round-1 tables and both CVE-fix databases; ``cache`` (a private JSON file) skips the slow database reads."""
    if cache is not None and cache.is_file():
        return Existing.load(json.loads(cache.read_text(encoding="utf-8")))
    old = Existing()
    for row in read_jsonl(codebench / "work" / "pairs.jsonl"):
        old.advisories.update(row["advisories"])
        old.cves.update(row["cves"])
        old.commits.update(c.lower() for c in row["commits"])
        old.repos.update(repo_of(r) for r in row["repos"])
        old.before_shas.update((row["before_sha"], row["after_sha"]))
        old.sources["codebench_pairs"] += 1
    for row in read_jsonl(codebench / "work" / "unchanged.jsonl"):
        old.commits.add(row["commit"].lower())
        old.repos.add(repo_of(row["repo"]))
        old.before_shas.add(row["text_sha"])
        old.sources["codebench_unchanged"] += 1
    for row in read_jsonl(vul / "work" / "mine_targets.jsonl"):
        old.advisories.update(row["advisories"])
        old.commits.add(row["sha"].lower())
        old.repos.add(repo_of(row["repo"]))
        old.sources["mine_targets"] += 1
    for name in ("cvefixes", "morefixes"):
        db = sqlite3.connect(f"file:{vul / 'work' / (name + '.sqlite')}?mode=ro", uri=True)
        for cve_id, sha, repo_url in db.execute("SELECT DISTINCT cve_id, hash, repo_url FROM fixes"):
            if name == "cvefixes":
                old.cves.add(str(cve_id))
                old.commits.add(str(sha).lower())
                old.repos.add(_repo_from_url(str(repo_url)))
            else:
                old.more_cves.add(str(cve_id))
                old.more_commits.add(str(sha).lower())
            old.sources[f"{name}_fix_rows"] += 1
        db.close()
    if cache is not None:
        write_json(cache, old.dump())
    return old


def advisory_records(checkout: Path) -> list[dict[str, Any]]:
    """Reviewed, not withdrawn PyPI and npm advisories with their GitHub fix-commit references."""
    out = []
    for path in sorted((checkout / "advisories" / "github-reviewed").rglob("*.json")):
        if path.stat().st_size > MAX_ADVISORY_BYTES:
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        ecosystems = sorted(
            {
                str(a.get("package", {}).get("ecosystem"))
                for a in doc.get("affected") or []
                if isinstance(a, dict) and a.get("package", {}).get("ecosystem") in {"PyPI", "npm"}
            }
        )
        if not ecosystems or doc.get("withdrawn"):
            continue
        commits = []
        for ref in doc.get("references") or []:
            m = COMMIT_URL.match(str(ref.get("url", ""))) if isinstance(ref, dict) else None
            if m:
                commits.append(
                    {"repo": f"{m.group(1)}/{m.group(2)}".lower().removesuffix(".git"), "sha": m.group(3).lower()}
                )
        out.append(
            {
                "id": str(doc.get("id")),
                "aliases": sorted(str(a) for a in doc.get("aliases") or []),
                "published": doc.get("published"),
                "withdrawn": None,
                "ecosystems": ecosystems,
                "cwes": sorted(str(c) for c in (doc.get("database_specific") or {}).get("cwe_ids") or []),
                "commits": commits,
            }
        )
    return out


def select_targets(
    root: Path, codebench: Path, vul: Path, *, allow_morefixes: bool = False, allow_known_repos: bool = False
) -> dict[str, Any]:
    """Pick the advisories and fix commits of ``test2`` and write ``work/ghsa.jsonl`` and ``work/mine_targets.jsonl``.

    An advisory or commit is out when round 1's core data holds its GHSA id, a CVE alias or the commit. MoreFixes-only
    commits (``allow_morefixes``) and repositories round 1 already scanned (``allow_known_repos``) are kept out unless
    asked for; the report counts what each of the four settings would give.
    """
    os.umask(0o077)
    private_dir(root / "work")
    old = load_existing(codebench, vul, root / "work" / "existing.json")
    records = advisory_records(root / "raw" / "ghsa")
    stats: Counter[str] = Counter()
    stats["advisories_reviewed_pypi_npm"] = len(records)
    tiers: dict[tuple[bool, bool], dict[str, set[Any]]] = {
        (m, r): {"advisories": set(), "commits": set(), "repos": set()} for m in (False, True) for r in (False, True)
    }
    keep: list[dict[str, Any]] = []
    by_commit: dict[tuple[str, str], set[str]] = {}
    for adv in records:
        if not adv["commits"]:
            stats["no_commit_reference"] += 1
            continue
        stats["with_commit_reference"] += 1
        cves = {a for a in adv["aliases"] if a.startswith("CVE-")}
        if adv["id"] in old.advisories:
            stats["excluded_ghsa_id_in_existing"] += 1
            continue
        if cves & old.cves:
            stats["excluded_cve_id_in_existing"] += 1
            continue
        fresh = []
        for c in adv["commits"]:
            if not SHA.match(c["sha"]):
                stats["skipped_abbreviated_sha"] += 1
                continue
            if not REPO.match(c["repo"]):
                stats["skipped_bad_repo_name"] += 1
                continue
            if c["sha"] in old.commits:
                stats["excluded_commit_in_existing"] += 1
                continue
            needs_more = c["sha"] in old.more_commits or bool(cves & old.more_cves)
            needs_repo = c["repo"] in old.repos
            stats["morefixes_only"] += needs_more
            stats["known_repository"] += needs_repo
            for (more, repo), tier in tiers.items():
                if (more or not needs_more) and (repo or not needs_repo):
                    tier["advisories"].add(adv["id"])
                    tier["commits"].add(c["sha"])
                    tier["repos"].add(c["repo"])
            if (allow_morefixes or not needs_more) and (allow_known_repos or not needs_repo):
                fresh.append(c)
        if not fresh:
            continue
        keep.append(adv | {"commits": fresh})
        for c in fresh:
            by_commit.setdefault((c["repo"], c["sha"]), set()).add(adv["id"])
    rows = [
        {"repo": repo, "sha": sha, "role": "ghsa", "advisories": sorted(ids)}
        for (repo, sha), ids in sorted(by_commit.items())
    ]
    write_jsonl(root / "work" / "ghsa.jsonl", sorted(keep, key=lambda a: a["id"]))
    write_jsonl(root / "work" / "mine_targets.jsonl", rows)
    report = {
        "schema_version": 1,
        "stage": "select",
        "generated_at": now(),
        "allow_morefixes": allow_morefixes,
        "allow_known_repos": allow_known_repos,
        "existing_data": dict(sorted(old.sources.items())),
        "counts": dict(sorted(stats.items())),
        "tiers": {
            f"morefixes={'allowed' if m else 'excluded'},repositories={'allowed' if r else 'new only'}": {
                "advisories": len(t["advisories"]),
                "fix_commits": len(t["commits"]),
                "repositories": len(t["repos"]),
            }
            for (m, r), t in tiers.items()
        },
        "selected": {
            "advisories": len(keep),
            "fix_commits": len(rows),
            "repositories": len({r["repo"] for r in rows}),
            "by_ecosystem": dict(sorted(Counter(e for a in keep for e in a["ecosystems"]).items())),
        },
    }
    write_json(root / "reports" / "test2-select.json", report)
    return report


def fetch_targets(root: Path, *, workers: int = 8, interval: float = 1.0, limit: int | None = None) -> dict[str, Any]:
    """Fetch the selected commits (transfer node); at most ``MAX_CHANGED_FILES`` changed source files per commit."""
    config = FetchConfig(max_changed_files=MAX_CHANGED_FILES)
    report = fetch(root, workers=workers, interval=interval, config=config, limit=limit)
    write_json(root / "reports" / "test2-fetch.json", report)
    return report


def build_heldout(layout: Layout, old_codebench: Path, vul_root: Path) -> dict[str, Any]:
    """Filter, de-duplicate and shard the fetched commits; every pair is in the ``test`` split of this root."""
    from .build import manifest, merge_pairs, merge_unchanged, write_file
    from .sources import RawPair, RawUnchanged, read_ghsa

    os.umask(0o077)
    old = load_existing(old_codebench, vul_root, layout.work / "existing.json")
    dropped: Counter[str] = Counter()
    raw_unchanged: list[RawUnchanged] = []
    raw: list[RawPair] = list(read_ghsa(layout.root, raw_unchanged))
    for pair in raw:
        if pair.commit in old.commits or set(pair.advisories) & old.advisories or set(pair.cves) & old.cves:
            raise CodeBenchError(f"{pair.commit} overlaps the existing data; select was bypassed")
    pairs = []
    for row in merge_pairs(raw, dropped):
        if {row["before_sha"], row["after_sha"]} & old.before_shas:
            dropped["ghsa:overlap_content"] += 1
        else:
            pairs.append(row)
    texts = {r["id"]: r.pop("_text") for r in pairs}
    known = {r["before_sha"] for r in pairs} | {r["after_sha"] for r in pairs} | old.before_shas
    unchanged_items = merge_unchanged(raw_unchanged, known, dropped)
    unchanged = [row for row, _ in unchanged_items]
    unchanged_text = {row["id"]: text for row, text in unchanged_items}
    for row in [*pairs, *unchanged]:
        row["split"], row["group"] = SPLIT, row.get("repos", [row.get("repo")])[0]
        row["repo_seen"] = bool(set(row.get("repos", [row.get("repo")])) & old.repos)  # round 1 scanned this repository
    for shard in range(SHARDS):
        for kind in KINDS:
            private_dir(layout.shard_dir(SPLIT, shard) / kind)
    for row in pairs:
        before, after = texts[row["id"]]
        write_file(layout, row, "b", before)
        write_file(layout, row, "a", after)
    for row in unchanged:
        write_file(layout, row, "u", unchanged_text[row["id"]])
    write_jsonl(layout.pairs, sorted(pairs, key=lambda r: r["id"]))
    write_jsonl(layout.unchanged, sorted(unchanged, key=lambda r: r["id"]))
    body = manifest(pairs, unchanged, dropped, seed="test2")
    body["splits"].pop("dev", None)
    body["evaluated"] = {"test": False}
    body["name"] = "test2"
    body["raw_changed_files"] = {"ghsa": len(raw)}
    body["overlap_with_existing"] = overlap_report(pairs, unchanged, old)
    body["manifest_sha256"] = ids_sha256([f"test:{body['splits']['test']['ids_sha256']}"])
    write_json(layout.split_manifest, body)
    write_json(layout.reports / "test2-files.json", file_manifest(pairs, unchanged))
    return body


def overlap_report(pairs: list[dict[str, Any]], unchanged: list[dict[str, Any]], old: Existing) -> dict[str, int]:
    """Counts of test2 ids, commits, repositories and file contents that round 1's core data also holds (ids, commits
    and file contents must be 0; repositories are 0 unless ``allow_known_repos`` was used) and, separately, the commits
    MoreFixes also holds (not used by this benchmark; nonzero only with ``allow_morefixes``)."""
    advisories = {a for r in pairs for a in r["advisories"]}
    cves = {c for r in pairs for c in r["cves"]}
    commits = {c for r in pairs for c in r["commits"]} | {r["commit"] for r in unchanged}
    repos = {x for r in pairs for x in r["repos"]} | {r["repo"] for r in unchanged}
    blobs = {r["before_sha"] for r in pairs} | {r["after_sha"] for r in pairs} | {r["text_sha"] for r in unchanged}
    return {
        "ghsa_ids": len(advisories & old.advisories),
        "cve_ids": len(cves & old.cves),
        "fix_commits": len(commits & old.commits),
        "repositories": len(repos & old.repos),
        "file_contents": len(blobs & old.before_shas),
        "morefixes_commits_allowed": len(commits & old.more_commits),
    }


def file_manifest(pairs: list[dict[str, Any]], unchanged: list[dict[str, Any]]) -> dict[str, Any]:
    """Private manifest: advisory ids, repository, commit and SHA-256 of every file (stays on the cluster)."""
    return {
        "schema_version": 1,
        "created_at": now(),
        "pairs": [
            {k: r[k] for k in ("id", "advisories", "cves", "repos", "commits", "language", "before_sha", "after_sha")}
            for r in sorted(pairs, key=lambda r: r["id"])
        ],
        "unchanged": [
            {k: r[k] for k in ("id", "repo", "commit", "language", "text_sha")}
            for r in sorted(unchanged, key=lambda r: r["id"])
        ],
        "sha256_of_ids": ids_sha256([r["id"] for r in pairs] + [r["id"] for r in unchanged]),
    }


def _new_repositories(layout: Layout, tools: list[str], run: str, reps: int) -> dict[str, Any]:
    """The same scoring on the pairs and unchanged files of repositories round 1 never scanned."""
    from .report import evaluate_report, load_frame

    try:
        frame = load_frame(layout, "test", reps, only=lambda row: not row["repo_seen"])
    except CodeBenchError:
        return {"pairs": 0}
    return {"pairs": frame.n_pairs, **evaluate_report(layout, frame, dict.fromkeys(tools, run), "test")}


def claim_lock(layout: Layout, info: dict[str, Any]) -> Path:
    """Create ``reports/LOCKED_EVAL_TEST2.json`` exclusively (the round-1 ``LOCKED_EVAL.json`` is a different, spent file)."""
    path = layout.reports / LOCK_NAME
    private_dir(path.parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        prev = json.loads(path.read_text(encoding="utf-8")) if path.stat().st_size else {}
        raise CodeBenchError(
            f"the test2 evaluation already ran (started {prev.get('started')}, name {prev.get('name')}); {path} records it"
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"started": now(), **info}, fh, indent=2)
    return path


def locked_test2(
    layout: Layout,
    name: str,
    trees: Mapping[str, Path | None],
    code_sha: str,
    *,
    reps: int = 1000,
    others: tuple[str, ...] = ("bandit", "eslint"),
) -> Path:
    """The one-time test2 evaluation: kestrix (the active code tree) and the other kestrix trees in ``trees`` (label to
    path, tool name ``kestrix@label``), Bandit and ESLint, scanned and scored on the frozen set. Claims the lock first."""
    from .common import SHARDS, file_sha256, write_json
    from .metrics import MARGIN, SEED, evaluate_tool, read_findings
    from .report import LOCKED_REPORT, evaluate_report, load_frame, paired_change
    from .scan import scan_shard

    manifest = json.loads(layout.split_manifest.read_text(encoding="utf-8"))
    if manifest.get("name") != "test2" or manifest["evaluated"] != {"test": False}:
        raise CodeBenchError("this root does not hold an unevaluated test2 set")
    tools = ["kestrix", *(f"kestrix@{label}" for label in sorted(trees)), *others]
    claim = claim_lock(
        layout,
        {
            "name": name,
            "code_sha": code_sha,
            "tools": tools,
            "kestrix_trees": {k: str(v) for k, v in trees.items()},
            "split_manifest_sha256": manifest["manifest_sha256"],
            "pairs_sha256": file_sha256(layout.pairs),
        },
    )
    run = f"locked-{name}"
    for tool in tools:
        tree = trees.get(tool.partition("@")[2]) if "@" in tool else None
        for shard in range(SHARDS):
            scan_shard(layout, tool, "test", shard, run=run, code_sha=code_sha, locked=True, tree=tree)
    frame = load_frame(layout, "test", reps)
    body: dict[str, Any] = {
        "schema_version": 1,
        "split": "test2",
        "name": name,
        "generated_at": now(),
        "code_sha": code_sha,
        "bootstrap": {"resamples": reps, "seed": SEED, "unit": "repository", "margin_lines": MARGIN},
        "split_manifest_sha256": manifest["manifest_sha256"],
        "test_data": manifest["splits"]["test"],
        "overlap_with_existing": manifest["overlap_with_existing"],
        **evaluate_report(layout, frame, dict.fromkeys(tools, run), "test"),
    }
    body["new_repositories_only"] = _new_repositories(layout, tools, run, reps)
    if trees:
        label = sorted(trees)[0]
        evals = {
            t: evaluate_tool(frame, "kestrix", read_findings(layout, run, t, SHARDS))
            for t in ("kestrix", f"kestrix@{label}")
        }
        body["paired_final_vs_" + label] = paired_change(frame, evals[f"kestrix@{label}"], evals["kestrix"])
    out = layout.reports / LOCKED_REPORT.format(name=name)
    write_json(out, body)
    done = json.loads(claim.read_text(encoding="utf-8")) | {
        "finished": now(),
        "report": out.name,
        "report_sha256": file_sha256(out),
    }
    write_json(claim, done)
    return out


__all__ = ["LOCK_NAME", "build_heldout", "fetch_targets", "locked_test2", "select_targets"]
