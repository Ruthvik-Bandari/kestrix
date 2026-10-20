# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Quality checks over the acquired vulnerability data (Slurm CPU job, offline).

Before reading anything, every archive is re-hashed against its pinned SHA-256 and every git
checkout against its acquisition manifest. The dumps are then streamed into private working
databases (``work/<source>.sqlite``, see ``dump.py``), and the report is computed from those.
The report is aggregate: counts, languages, CWE ids, dates and hashes, never code, commit
messages or CVE text, so it is safe to commit.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from kestrixbench.acquire import manifest as git_manifest

from .acquire import digests
from .dump import load
from .paths import LANGUAGES, content_reason, path_reason
from .sources import ARCHIVES, GIT_SOURCES

MOREFIXES_MIN_SCORE = 65  # the MoreFixes README: "use a threshold preferably over ~65 to reduce noise"
TEST_WINDOW_START = "2024-10-01"  # CVEs published after 2024-09-30 (plan: after the base model's release)
MAX_ADVISORY_BYTES = 1024 * 1024
TARGET = tuple(LANGUAGES.values())
COMMIT_URL = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})", re.IGNORECASE)
DUMPS = {"cvefixes": ("sqlite", "CVEfixes_v1.0.8.zip"), "morefixes": ("pg", "dump-2026-06-20.sql.gz")}


class QCError(RuntimeError):
    pass


def verify_archives(root: Path) -> dict[str, str]:
    """Re-hash every archive against its pin; return {relative path: sha256}."""
    verified: dict[str, str] = {}
    for source in ARCHIVES:
        for artifact in source.artifacts:
            if artifact.sha256 is None:
                raise QCError(f"{source.name}/{artifact.filename}: sha256 is not pinned in sources.py")
            path = root / "raw" / source.name / artifact.filename
            md5, sha = digests(path)
            if (md5, sha) != (artifact.md5, artifact.sha256) or path.stat().st_size != artifact.size:
                raise QCError(f"{source.name}/{artifact.filename}: does not match its pin")
            verified[f"{source.name}/{artifact.filename}"] = sha
    return verified


def verify_git(root: Path) -> dict[str, str]:
    """Re-check each checkout against its acquisition manifest; return {source: content sha256}."""
    out: dict[str, str] = {}
    for source in GIT_SOURCES:
        recorded = json.loads((root / "manifests" / f"{source.name}.json").read_text())
        current = git_manifest(source, root / "raw" / source.name)
        if current["files"] != recorded["files"]:
            raise QCError(f"{source.name}: files changed since acquisition")
        out[source.name] = str(current["content_sha256"])
    return out


def _load_one(args: tuple[str, str, str, str]) -> tuple[str, dict[str, int]]:
    name, kind, src, out = args
    return name, load(kind, Path(src), Path(out))


def load_dumps(root: Path, pins: dict[str, str], rebuild: bool) -> None:
    """(Re)build ``work/<source>.sqlite`` when missing, stale or ``rebuild`` is set; both in parallel."""
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    jobs = []
    for name, (kind, filename) in DUMPS.items():
        db, stamp = work / f"{name}.sqlite", work / f"{name}.sqlite.sha256"
        pin = pins[f"{name}/{filename}"]
        if rebuild or not db.exists() or not stamp.exists() or stamp.read_text().strip() != pin:
            stamp.unlink(missing_ok=True)
            jobs.append((name, kind, str(root / "raw" / name / filename), str(db)))
    with ProcessPoolExecutor(max_workers=max(1, len(jobs))) as pool:
        for name, rows in pool.map(_load_one, jobs):
            print(f"qc: loaded {name}: {rows}")
            (work / f"{name}.sqlite.sha256").write_text(pins[f"{name}/{DUMPS[name][1]}"] + "\n")


def fix_commits_sql(source: str) -> str:
    """The fix-commit relation for a source (MoreFixes: score at or above the recommended threshold)."""
    where = f"WHERE score >= {MOREFIXES_MIN_SCORE}" if source == "morefixes" else ""
    return f"SELECT DISTINCT cve_id, hash, repo_url FROM fixes {where}"  # noqa: S608 - constant


def _year(date: str | None) -> str:
    return (date or "")[:4] or "unknown"


def _top(counter: Counter[str], n: int = 25) -> dict[str, int]:
    return dict(counter.most_common(n))


def source_report(db: sqlite3.Connection, source: str) -> dict[str, Any]:
    stats = dict(db.execute("SELECT key, value FROM load_stats"))
    fixes = fix_commits_sql(source)
    db.execute(f"CREATE TEMP TABLE fx AS {fixes}")
    db.execute("CREATE INDEX temp.fx_hash ON fx(hash)")
    report: dict[str, Any] = {
        "dump_rows": {k[5:]: v for k, v in stats.items() if k.startswith("rows:")},
        "file_changes_by_language": _top(Counter({k[6:]: v for k, v in stats.items() if k.startswith("files:")}), 40),
        "method_changes_by_language": _top(
            Counter({k[8:]: v for k, v in stats.items() if k.startswith("methods:")}), 40
        ),
        "fixes": {
            "rows": db.execute("SELECT count(*) FROM fixes").fetchone()[0],
            "used_cves": db.execute("SELECT count(DISTINCT cve_id) FROM fx").fetchone()[0],
            "used_commits": db.execute("SELECT count(DISTINCT hash) FROM fx").fetchone()[0],
            "used_repositories": db.execute("SELECT count(DISTINCT lower(repo_url)) FROM fx").fetchone()[0],
        },
    }
    if source == "morefixes":
        report["fixes"]["score_buckets"] = dict(
            db.execute(
                "SELECT CASE WHEN score IS NULL THEN 'null' WHEN score >= ? THEN 'at_or_above_threshold' "
                "ELSE 'below_threshold' END AS b, count(DISTINCT hash) FROM fixes GROUP BY b",
                (MOREFIXES_MIN_SCORE,),
            )
        )
        report["fixes"]["score_threshold"] = MOREFIXES_MIN_SCORE
    dates = db.execute("SELECT min(published_date), max(published_date), count(*) FROM cve").fetchone()
    report["cve_table"] = {"rows": dates[2], "published_min": dates[0], "published_max": dates[1]}
    per_language: dict[str, Any] = {}
    for language in TARGET:
        per_language[language] = _language_report(db, language)
    report["target_languages"] = per_language
    return report


def _language_report(db: sqlite3.Connection, language: str) -> dict[str, Any]:
    reasons: Counter[str] = Counter()
    commits: set[str] = set()
    seen: set[str] = set()
    cursor = db.execute(  # streamed: the full file texts of bundled JavaScript run to gigabytes
        "SELECT f.file_change_id, f.hash, coalesce(f.new_path, f.old_path, f.filename), f.code_before, f.code_after "
        "FROM file_change f WHERE f.language = ? AND f.hash IN (SELECT hash FROM fx)",
        (language,),
    )
    for fc_id, sha, path, before, after in cursor:
        if fc_id in seen:
            continue
        seen.add(fc_id)
        commits.add(sha)
        reason = path_reason(path or "") or content_reason(before) or content_reason(after)
        reasons[reason or "kept"] += 1
    methods = dict(
        db.execute(
            "SELECT m.before_change, count(*) FROM method_change m JOIN file_change f "
            "ON f.file_change_id = m.file_change_id WHERE f.language = ? AND f.hash IN (SELECT hash FROM fx) "
            "GROUP BY m.before_change",
            (language,),
        )
    )
    cves = db.execute(
        "SELECT DISTINCT fx.cve_id, c.published_date FROM fx JOIN file_change f ON f.hash = fx.hash "
        "LEFT JOIN cve c ON c.cve_id = fx.cve_id WHERE f.language = ?",
        (language,),
    ).fetchall()
    cve_ids = {c for c, _ in cves}
    published = sorted(p for _, p in cves if p)
    cwes: Counter[str] = Counter()
    for (cwe,) in db.execute(
        "SELECT w.cwe_id FROM (SELECT DISTINCT fx.cve_id FROM fx JOIN file_change f ON f.hash = fx.hash "
        "WHERE f.language = ?) v JOIN cwe_classification w ON w.cve_id = v.cve_id",
        (language,),
    ):
        cwes[str(cwe)] += 1
    projects = db.execute(
        "SELECT count(DISTINCT lower(fx.repo_url)) FROM fx JOIN file_change f ON f.hash = fx.hash WHERE f.language = ?",
        (language,),
    ).fetchone()[0]
    total = len(seen)
    return {
        "file_changes": total,
        "commits": len(commits),
        "cves": len(cve_ids),
        "projects": projects,
        "method_changes_source_labels": {
            "before_fix_rows_labelled_vulnerable": methods.get(1, 0),
            "after_fix_rows_labelled_not_vulnerable": methods.get(0, 0),
        },
        "file_filter_reasons": dict(sorted(reasons.items())),
        "file_filter_share": {k: round(v / total, 4) for k, v in sorted(reasons.items())} if total else {},
        "cwe_top": _top(cwes),
        "cve_published_min": published[0] if published else None,
        "cve_published_max": published[-1] if published else None,
        "cves_by_year": dict(sorted(Counter(_year(p) for _, p in cves).items())),
        "cves_in_test_window": sum(1 for p in published if p >= TEST_WINDOW_START),
    }


def advisories(checkout: Path) -> Iterator[dict[str, Any]]:
    """Reviewed PyPI and npm advisories as compact records (id, aliases, dates, CWEs, fix commits)."""
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
        if not ecosystems:
            continue
        commits = []
        for ref in doc.get("references") or []:
            m = COMMIT_URL.match(str(ref.get("url", ""))) if isinstance(ref, dict) else None
            if m:
                commits.append({"repo": f"{m.group(1)}/{m.group(2)}".lower(), "sha": m.group(3).lower()})
        specific = doc.get("database_specific") or {}
        yield {
            "id": str(doc.get("id")),
            "aliases": sorted(str(a) for a in doc.get("aliases") or []),
            "published": doc.get("published"),
            "withdrawn": doc.get("withdrawn"),
            "ecosystems": ecosystems,
            "cwes": sorted(str(c) for c in specific.get("cwe_ids") or []),
            "commits": commits,
        }


def ghsa_report(root: Path, fix_hashes: dict[str, set[str]]) -> dict[str, Any]:
    out = root / "work" / "ghsa.jsonl"
    records = list(advisories(root / "raw" / "ghsa"))
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")
    out.chmod(0o600)
    report: dict[str, Any] = {}
    for eco in ("PyPI", "npm"):
        rows = [r for r in records if eco in r["ecosystems"] and not r["withdrawn"]]
        shas = {c["sha"] for r in rows for c in r["commits"]}
        published = sorted(str(r["published"]) for r in rows if r["published"])
        covered = {name: sum(1 for s in shas if hashes_by_prefix(hashes, s)) for name, hashes in fix_hashes.items()}
        report[eco] = {
            "advisories": len(rows),
            "with_cve_alias": sum(1 for r in rows if any(a.startswith("CVE-") for a in r["aliases"])),
            "with_fix_commit_reference": sum(1 for r in rows if r["commits"]),
            "distinct_fix_commits": len(shas),
            "fix_commits_present_in": covered,
            "published_min": published[0] if published else None,
            "published_max": published[-1] if published else None,
            "published_in_test_window": sum(1 for p in published if p >= TEST_WINDOW_START),
            "cwe_top": _top(Counter(c for r in rows for c in r["cwes"])),
        }
    report["withdrawn_skipped"] = sum(1 for r in records if r["withdrawn"])
    return report


def hashes_by_prefix(hashes: set[str], sha: str) -> set[str]:
    """Full hashes that start with ``sha`` (advisories sometimes cite abbreviated commits)."""
    if len(sha) == 40:
        return {sha} if sha in hashes else set()
    return {h for h in hashes if h.startswith(sha)}


def sven_rows(checkout: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    for path in sorted((checkout / "data_train_val").glob("*/*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                yield path.parent.name, json.loads(line)


def sven_report(root: Path) -> dict[str, Any]:
    per_split: dict[str, Counter[str]] = {}
    cwes: Counter[str] = Counter()
    repos: set[str] = set()
    for split, row in sven_rows(root / "raw" / "sven"):
        language = "python" if str(row.get("file_name", "")).endswith(".py") else "c_cpp"
        per_split.setdefault(split, Counter())[language] += 1
        if language == "python":
            cwes[str(row.get("vul_type"))] += 1
            repos.add("/".join(str(row.get("commit_link", "")).split("/")[1:3]).lower())
    return {
        "pairs_by_split_and_language": {s: dict(c) for s, c in sorted(per_split.items())},
        "python_pairs_by_cwe": dict(sorted(cwes.items())),
        "python_projects": len(repos),
    }


def run(root: Path, *, rebuild: bool = False) -> dict[str, Any]:
    pins = verify_archives(root)
    git = verify_git(root)
    load_dumps(root, pins, rebuild)
    report: dict[str, Any] = {
        "schema_version": 1,
        "verified": {"archives_sha256": pins, "git_content_sha256": git},
        "sources": {},
        "test_window_start": TEST_WINDOW_START,
    }
    fix_hashes: dict[str, set[str]] = {}
    for name in DUMPS:
        db = sqlite3.connect(root / "work" / f"{name}.sqlite")
        report["sources"][name] = source_report(db, name)
        fix_hashes[name] = {
            h
            for (h,) in db.execute(
                "SELECT DISTINCT f.hash FROM file_change f JOIN fx ON fx.hash = f.hash WHERE f.language IN (?,?,?)",
                TARGET,
            )
        }
        db.close()
    report["sources"]["ghsa"] = ghsa_report(root, fix_hashes)
    report["sources"]["sven"] = sven_report(root)
    report["licenses"] = {s.name: s.license_spdx for s in ARCHIVES} | {s.name: s.license_spdx for s in GIT_SOURCES}
    return report
