# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Real-browsing link false alarms: a benign full-URL sample from the Common Crawl URL index.

``ccindex.py`` (transfer node) writes ``raw/commoncrawl/<crawl>/urls.jsonl``; ``build_realurls`` turns it into the
same ``work/`` files the link benchmark uses (``kind`` ``realurl``), so ``features`` and the locked test run
unchanged. URLs are text only and are never fetched. All items are benign by assumption: popular sites and the
user-content hosts, which can hold abuse the index does not label, so the rates are upper bounds on false alarms.

Cohorts (the ``source`` of each item): ``top_domain`` (pages of sampled Majestic domains) and one per user-content
platform (``github.io`` ...). The split group is the Majestic domain for ``top_domain`` and the full host for a
platform page (every user site is its own group; the registered domain would put a whole platform on one side).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from kestrix.core.errors import Rejected
from kestrix.forensics.url import analyze_url
from kestrixmailbench.metrics import REPS, SEED, Frame, rate

from .ccindex import CRAWL, PLATFORMS, TOP_COHORT, host_of
from .common import BENIGN, Layout, LinkFileBenchError, now, read_jsonl, seeded_key, write_json, write_jsonl
from .common import SEED as SEED_KEY
from .links import exact_key, url_id
from .metrics import RANK, TOP

PLATFORM_CAP = (
    5000  # URLs kept per platform: whole hosts in seeded order until the cap, so one platform cannot dominate
)
MIN_FINDING_ITEMS = 3
LEVELS = (("low_or_higher", 1), ("medium_or_higher", 2), ("high", 3))


def cohort_of(host: str, declared: str) -> str:
    """The cohort of a page: a named platform when the host is a user subdomain of it, else the declared one."""
    for suffix in PLATFORMS:
        if host.endswith("." + suffix) and host != "www." + suffix:
            return suffix
    return TOP_COHORT if declared == TOP_COHORT else declared


def group_of_page(cohort: str, host: str, domain: str) -> str:
    """Hashed split group: the host of a platform page, the sampled domain otherwise."""
    if cohort == TOP_COHORT:
        return "d" + hashlib.sha256(domain.encode()).hexdigest()[:16]
    return "h" + hashlib.sha256(host.encode()).hexdigest()[:16]


def _cap_platforms(kept: list[dict[str, Any]], dropped: Counter[str], cap: int = PLATFORM_CAP) -> list[dict[str, Any]]:
    """Keep at most ``cap`` URLs per platform cohort: whole hosts, in seeded-hash order."""
    by_host: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in kept:
        if item["source"] != TOP_COHORT:
            by_host.setdefault((item["source"], item["group"]), []).append(item)
    taken: Counter[str] = Counter()
    keep_ids = {item["id"] for item in kept if item["source"] == TOP_COHORT}
    for (cohort, _group), items in sorted(by_host.items(), key=lambda kv: seeded_key(SEED_KEY, "cap|" + kv[0][1])):
        if taken[cohort] + len(items) <= cap or taken[cohort] == 0:
            taken[cohort] += len(items)
            keep_ids |= {i["id"] for i in items}
        else:
            dropped[f"{cohort}|platform_cap"] += len(items)
    return [item for item in kept if item["id"] in keep_ids]


def build_realurls(raw: Path, layout: Layout, crawl: str = CRAWL) -> dict[str, Any]:
    """Filter, deduplicate and group the sampled URLs; write ``work/`` and ``reports/build.json`` (counts only)."""
    path = raw / "commoncrawl" / crawl / "urls.jsonl"
    if not path.is_file():
        raise LinkFileBenchError(f"missing {path}; run acquire-cc on the transfer node first")
    read: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    for row in read_jsonl(path):
        url = str(row["url"]).strip()
        host = host_of(url)
        cohort = cohort_of(host, str(row["cohort"]))
        read[cohort] += 1
        try:
            analyze_url(url)
        except Rejected as exc:
            dropped[f"{cohort}|{exc.reason.value}"] += 1
            continue
        key = exact_key(url)
        if key in seen:
            dropped[f"{cohort}|duplicate_exact"] += 1
            continue
        seen.add(key)
        ident = url_id(url)
        kept.append(
            {
                "id": ident,
                "source": cohort,
                "subset": cohort,
                "label": BENIGN,
                "year": None,
                "group": group_of_page(cohort, host, str(row["domain"])),
                "shard": int(ident[:8], 16) % layout.shards,
                "url": url,
            }
        )
    kept = _cap_platforms(kept, dropped)
    if len({k["id"] for k in kept}) != len(kept):
        raise LinkFileBenchError("URL id collision")
    kept.sort(key=lambda k: k["id"])
    for shard in range(layout.shards):
        write_jsonl(layout.raw_shard(shard), ({"id": k["id"], "url": k["url"]} for k in kept if k["shard"] == shard))
    write_jsonl(layout.meta, ({k: v for k, v in item.items() if k != "url"} for item in kept))
    report = {
        "schema_version": 1,
        "kind": "realurl",
        "generated_at": now(),
        "crawl": crawl,
        "read": dict(sorted(read.items())),
        "dropped": dict(sorted(dropped.items())),
        "kept": dict(sorted(Counter(k["source"] for k in kept).items())),
        "kept_total": len(kept),
        "groups": len({k["group"] for k in kept}),
        "https_share": round(sum(k["url"].startswith("https://") for k in kept) / max(1, len(kept)), 4),
    }
    write_json(layout.reports / "build.json", report)
    return report


def _has(frame: Frame, finding_id: str) -> np.ndarray:
    return np.array([any(f[0] == finding_id for f in r["findings"]) for r in frame.rows], dtype=bool)


def _cohort_report(frame: Frame, mask: np.ndarray, rank: np.ndarray, reps: int, seed: int) -> dict[str, Any]:
    n = int(mask.sum())
    rows = [frame.rows[int(i)] for i in np.flatnonzero(mask)]
    ids: Counter[str] = Counter()
    for row in rows:
        ids.update({f[0] for f in row["findings"]})
    common = [i for i, c in ids.most_common() if c >= MIN_FINDING_ITEMS]
    combos: Counter[str] = Counter()
    for row in rows:
        if RANK[row["level"]] >= 1:
            combos["+".join(sorted(f[0] for f in row["findings"] if RANK[f[1]] >= 1))] += 1
    return {
        "n": n,
        "groups": len({int(g) for g in frame.group[mask]}),
        "at_level": {name: rate(frame, mask, rank >= k, reps, seed) for name, k in LEVELS},
        "level_share": {
            name: round(float(((rank == k) & mask).sum()) / n, 6) if n else None
            for name, k in (("none", 0), ("low", 1), ("medium", 2), ("high", 3))
        },
        "finding_rate": {fid: rate(frame, mask, _has(frame, fid), reps, seed) for fid in common[:TOP]},
        "finding_items": dict(ids.most_common()),
        "low_or_higher_by_findings": dict(combos.most_common(TOP)),
        "https_share": round(sum(r["https"] for r in rows) / n, 4) if n else None,
    }


def realurl_report(frame: Frame, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """False-alarm rates and per-finding rates per cohort, with grouped bootstrap intervals."""
    rank = np.array([RANK[r["level"]] for r in frame.rows], dtype=np.int64)
    platform_names = [p for p in PLATFORMS if (frame.source == p).any()]
    cohorts = {TOP_COHORT: frame.source == TOP_COHORT, **{p: frame.source == p for p in platform_names}}
    cohorts["platforms_all"] = np.isin(frame.source, platform_names) if platform_names else np.zeros(len(frame), bool)
    cohorts["all"] = np.ones(len(frame), dtype=bool)
    https = np.array([r["https"] for r in frame.rows], dtype=bool)
    pathy = np.array([bool(r["path"] or r["query"]) for r in frame.rows], dtype=bool)
    top = cohorts[TOP_COHORT]
    shapes = {
        f"{TOP_COHORT}/{scheme}/{shape}": top & s & p
        for scheme, s in (("https", https), ("http", ~https))
        for shape, p in (("bare", ~pathy), ("path_or_query", pathy))
    }
    return {
        "items": len(frame),
        "cohorts": {
            name: _cohort_report(frame, mask, rank, reps, seed) for name, mask in cohorts.items() if mask.any()
        },
        "top_domain_by_shape": {
            name: {
                "n": int(mask.sum()),
                "low_or_higher": rate(frame, mask, rank >= 1, reps, seed),
                "medium_or_higher": rate(frame, mask, rank >= 2, reps, seed),
            }
            for name, mask in shapes.items()
            if mask.any()
        },
    }


__all__ = ["build_realurls", "realurl_report"]
