# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Per-repository licenses for the two-tier policy (plan: shipped weights train on permissive code only).

The flow keeps credentials off the cluster:

1. ``licenses-export`` (cluster) writes ``licenses/repos.txt``, the public ``owner/name`` list of
   every GitHub repository in the deduplicated pool.
2. ``licenses-fetch`` (the owner's machine) asks GitHub for each repository's SPDX id with the
   locally authenticated ``gh api repos/{owner}/{repo}``, throttled and cached.
3. ``licenses-import`` (cluster) validates the returned CSV and summarizes it.

Only ``permissive`` repositories form the pool for weights shipped with Kestrix. MPL and LGPL are
weak copyleft and kept apart; ``other`` (GitHub's NOASSERTION and licenses outside these lists),
``none`` and ``unknown`` are never treated as permissive.
"""

from __future__ import annotations

import csv
import io
import json
import re
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PERMISSIVE = {"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "0BSD", "Unlicense", "Zlib", "PSF-2.0"}
WEAK_COPYLEFT = re.compile(r"^(MPL-\d\.\d|LGPL-.*|EPL-\d\.\d|CDDL-\d\.\d)$")
COPYLEFT = re.compile(r"^(GPL-.*|AGPL-.*|EUPL-.*|OSL-3\.0|CC-BY-SA-.*)$")
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SPDX = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
CLASSES = ("permissive", "weak_copyleft", "copyleft", "other", "none", "unknown")
THROTTLE_S = 0.25
MIN_REMAINING = 50


def classify(spdx: str | None) -> str:
    if spdx is None or spdx in {"NOT_FOUND", "ERROR"}:
        return "unknown"
    if spdx == "NONE":
        return "none"
    if spdx in PERMISSIVE:
        return "permissive"
    if WEAK_COPYLEFT.match(spdx):
        return "weak_copyleft"
    if COPYLEFT.match(spdx):
        return "copyleft"
    return "other"


def _pool(root: Path) -> list[dict[str, Any]]:
    path = root / "work" / "deduped.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def github_name(repo_key: str) -> str | None:
    """``owner/name`` for a ``github.com/owner/name`` key, else None."""
    host, _, rest = repo_key.partition("/")
    return rest if host == "github.com" and REPO.match(rest) else None


def export(root: Path) -> int:
    repos = sorted({r["repo"] for r in _pool(root)})
    names = sorted({n for r in repos if (n := github_name(r))})
    out = root / "licenses"
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    (out / "repos.txt").write_text("".join(n + "\n" for n in names))
    (out / "non_github.txt").write_text("".join(r + "\n" for r in repos if not github_name(r)))
    return len(names)


def _gh(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60, check=False)  # noqa: S603,S607


def lookup(repo: str) -> str:
    """SPDX id of one repository: an id, ``NONE`` (no license), ``NOT_FOUND`` or ``ERROR``."""
    result = _gh("api", f"repos/{repo}", "--jq", '.license.spdx_id // "NONE"')
    if result.returncode == 0:
        value = result.stdout.strip()
        return value if SPDX.match(value) else "ERROR"
    if "404" in result.stderr or "Not Found" in result.stderr:
        return "NOT_FOUND"
    return "ERROR"


def _wait_for_rate_limit() -> None:
    result = _gh("api", "rate_limit", "--jq", ".resources.core | [.remaining, .reset] | @tsv")
    if result.returncode != 0:
        return
    remaining, reset = (int(x) for x in result.stdout.split())
    if remaining < MIN_REMAINING:
        time.sleep(max(0, reset - time.time()) + 5)


def fetch_table(repos_file: Path, out: Path) -> dict[str, int]:
    """Look up every repository (cached in ``<out>.cache.json``; ERROR entries are retried)."""
    repos = [line.strip() for line in repos_file.read_text().splitlines() if line.strip()]
    bad = [r for r in repos if not REPO.match(r)]
    if bad:
        raise ValueError(f"{len(bad)} malformed repository names, e.g. {bad[0]!r}")
    cache_path = out.with_name(out.name + ".cache.json")
    cache: dict[str, str] = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    for i, repo in enumerate(r for r in repos if cache.get(r, "ERROR") == "ERROR"):
        if i % 200 == 0:
            _wait_for_rate_limit()
            cache_path.write_text(json.dumps(cache, sort_keys=True))
        cache[repo] = lookup(repo)
        time.sleep(THROTTLE_S)
    cache_path.write_text(json.dumps(cache, sort_keys=True))
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["repo", "spdx_id", "license_class"])
    for repo in repos:
        writer.writerow([repo, cache[repo], classify(cache[repo])])
    out.write_text(buf.getvalue())
    return dict(Counter(classify(cache[r]) for r in repos))


def read_table(path: Path) -> dict[str, str]:
    """Validated ``{owner/name (lower-case): spdx id}``; any malformed row rejects the table."""
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    table: dict[str, str] = {}
    for n, row in enumerate(rows, start=2):
        repo, spdx = row.get("repo", ""), row.get("spdx_id", "")
        if not REPO.match(repo) or not SPDX.match(spdx):
            raise ValueError(f"{path.name}: line {n} is malformed")
        table[repo.lower()] = spdx
    return table


def license_of(record: dict[str, Any], table: dict[str, str]) -> str | None:
    name = github_name(record["repo"])
    return table.get(name.lower()) if name else None


def import_table(root: Path, table_path: Path) -> dict[str, Any]:
    table = read_table(table_path)
    expected = {line.strip().lower() for line in (root / "licenses" / "repos.txt").read_text().splitlines() if line}
    missing = sorted(expected - set(table))
    if missing:
        raise ValueError(f"license table misses {len(missing)} exported repositories")
    dest = root / "licenses" / "licenses.csv"
    dest.write_text(table_path.read_text())
    dest.chmod(0o600)
    repo_classes = Counter(classify(table[r]) for r in expected)
    spdx_counts = Counter(table[r] for r in expected)
    records: dict[str, Counter[str]] = defaultdict(Counter)
    for record in _pool(root):
        records[record["language"]][classify(license_of(record, table))] += 1
    return {
        "schema_version": 1,
        "permissive_spdx": sorted(PERMISSIVE),
        "repositories": len(expected),
        "repositories_by_class": {c: repo_classes.get(c, 0) for c in CLASSES},
        "repositories_by_spdx": dict(spdx_counts.most_common()),
        "records_by_language_and_class": {
            lang: {c: counts.get(c, 0) for c in CLASSES} for lang, counts in sorted(records.items())
        },
        "shipped_weight_pool_records": {lang: counts.get("permissive", 0) for lang, counts in sorted(records.items())},
    }
