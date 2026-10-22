# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Readers for the data ``kestrixvul`` already acquired on the cluster (nothing is downloaded here).

* **CVEfixes v1.0.8** (CC BY 4.0): the private working database ``work/cvefixes.sqlite`` that ``kestrixvul qc`` built
  from the pinned Zenodo archive. ``file_change`` holds the whole file before and after each fix commit.
* **GitHub Advisory Database fix commits** (CC BY 4.0, mined by ``kestrixvul mine-fetch`` from the public
  repositories): ``mine/commits/<sha>.json.gz`` with the changed files before and after, and up to three files the
  commit did not change, taken from its parent. Only commits that neither CVEfixes nor MoreFixes hold (role ``ghsa``)
  give file pairs; the files sampled from every mined commit (role ``ghsa`` or ``pool``) are the unchanged files.

Both readers yield plain records; filtering, de-duplication and the split are in ``build``.
"""

from __future__ import annotations

import gzip
import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .families import parse_cwes

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class RawPair:
    source: str  # cvefixes or ghsa
    repos: list[str]
    commit: str
    published: str
    cves: list[str]
    advisories: list[str]
    cwes: list[int]
    path: str
    before: str
    after: str


@dataclass
class RawUnchanged:
    source: str
    repo: str
    commit: str
    path: str
    text: str


def repo_name(url: str) -> str:
    """``owner/name`` lower-cased from a GitHub URL (or an ``owner/name`` string)."""
    stripped = re.sub(r"^https?://(www\.)?github\.com/", "", url.strip().rstrip("/")).removesuffix(".git")
    return "/".join(stripped.split("/")[:2]).lower()


def read_cvefixes(db_path: Path) -> Iterator[RawPair]:
    """Modified Python, JavaScript and TypeScript files of every CVEfixes fix commit, before and after."""
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cwes: dict[str, list[str]] = defaultdict(list)
    for cve_id, cwe_id in db.execute("SELECT cve_id, cwe_id FROM cwe_classification"):
        cwes[cve_id].append(cwe_id or "")
    published = dict(db.execute("SELECT cve_id, published_date FROM cve"))
    fixes: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"cves": set(), "repos": set()})
    for cve_id, sha, repo_url in db.execute("SELECT DISTINCT cve_id, hash, repo_url FROM fixes"):
        fixes[sha]["cves"].add(cve_id)
        fixes[sha]["repos"].add(repo_name(repo_url))
    hashes = [h for (h,) in db.execute("SELECT DISTINCT hash FROM file_change") if h in fixes]
    for sha in sorted(hashes):
        info = fixes[sha]
        cve_ids = sorted(c for c in info["cves"] if CVE_ID.match(c))
        number = parse_cwes([w for c in cve_ids for w in cwes.get(c, [])])
        dates = sorted(d for d in (published.get(c) for c in cve_ids) if d)
        rows = db.execute(
            "SELECT old_path, new_path, change_type, code_before, code_after FROM file_change WHERE hash = ?", (sha,)
        )
        for old_path, new_path, change_type, before, after in rows:
            if before is None or after is None or "ADD" in (change_type or "") or "DELETE" in (change_type or ""):
                continue
            yield RawPair(
                "cvefixes",
                sorted(info["repos"]),
                sha,
                dates[0][:10] if dates else "",
                cve_ids,
                [],
                number,
                new_path or old_path or "",
                before,
                after,
            )
    db.close()


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row: dict[str, Any] = json.loads(line)
                yield row


def read_ghsa(vul_root: Path, unchanged: list[RawUnchanged]) -> Iterator[RawPair]:
    """Changed files of the mined advisory fix commits; the sampled unchanged files are appended to ``unchanged``."""
    advisories = {row["id"]: row for row in _jsonl(vul_root / "work" / "ghsa.jsonl")}
    for target in sorted(_jsonl(vul_root / "work" / "mine_targets.jsonl"), key=lambda t: t["sha"]):
        path = vul_root / "mine" / "commits" / f"{target['sha']}.json.gz"
        if not path.is_file():
            continue
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            record = json.load(fh)
        repo = repo_name(target["repo"])
        for item in record.get("sampled", []):
            if item.get("text"):
                unchanged.append(RawUnchanged("ghsa", repo, target["sha"], item["path"], item["text"]))
        if target["role"] != "ghsa":
            continue
        advs = [advisories[a] for a in target["advisories"] if a in advisories]
        cve_ids = sorted({a for adv in advs for a in adv.get("aliases", []) if CVE_ID.match(a)})
        number = parse_cwes([w for adv in advs for w in adv.get("cwes", [])])
        dates = sorted(adv["published"] for adv in advs if adv.get("published"))
        for item in record["files"]:
            if item.get("unreadable") or item.get("before") is None or item.get("after") is None:
                continue
            yield RawPair(
                "ghsa",
                [repo],
                target["sha"],
                dates[0][:10] if dates else "",
                cve_ids,
                sorted(target["advisories"]),
                number,
                item["path"],
                item["before"],
                item["after"],
            )
