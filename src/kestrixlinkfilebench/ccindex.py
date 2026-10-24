# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benign full URLs from the Common Crawl URL index (transfer node only; standard library only).

Only URL text is fetched: the index lines (SURT key, timestamp, JSON with the crawled URL, status and MIME type),
never a page. ``cluster.idx`` (one line per 3,000-line block of the sorted index: SURT key, file, offset, length)
is downloaded once; a block is then one HTTP range request of about 250 KB, so a domain needs one or two small
requests and no index-server query. Two samples, both seeded:

* ``top_domain``: domains drawn from the top ``RANK_LIMIT`` of the Majestic Million; per domain up to
  ``per_domain`` URLs (HTTP status 200, HTML) from one or two random blocks of the domain's key range;
* user-content hosts: for each platform (``github.io``, ``vercel.app``, ...) random blocks inside the platform's
  key range (every ``*.platform`` host is contiguous in the index), at most ``per_host`` URLs per host.

Terms: https://commoncrawl.org/terms-of-use (limited license, the crawled content stays under its owners' terms,
no use that infringes their rights or collects personal data; recorded in ``docs/research/linkfile-benchmark.md``).
Only aggregates leave the cluster. Requests carry a descriptive User-Agent, run on a few threads and back off on
429 and 5xx answers.
"""

from __future__ import annotations

import csv
import gzip
import http.client
import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .common import SEED, Layout, LinkFileBenchError, file_sha256, now, seeded_key, write_json, write_private

CRAWL = "CC-MAIN-2026-43"
DATA_BASE = "https://data.commoncrawl.org"
TERMS_URL = "https://commoncrawl.org/terms-of-use"
USER_AGENT = "kestrix-linkfilebench/1 (academic benchmark of a URL checker; text of index lines only)"
RANK_LIMIT = 100_000
TOP_DOMAINS = 5_000
CANDIDATES = 12_000
BATCH = 100
PER_DOMAIN = 10
PLATFORM_BLOCKS = 150
PER_HOST = 2
BLOCKS_PER_DOMAIN = 2
MAX_URL_CHARS = 2048
WORKERS = 2
PAUSE_SECONDS = 0.5  # each worker waits this long after a request, so the whole run stays near 4 requests a second
TOP_COHORT = "top_domain"
# The user-content hosts named in the task; each is one cohort named after its suffix.
PLATFORMS = ("github.io", "vercel.app", "netlify.app", "pages.dev", "blogspot.com", "wordpress.com")
HTML_MIMES = ("text/html", "application/xhtml+xml")

Fetch = Callable[[str, int, int], bytes]


class BlockedError(LinkFileBenchError):
    """The server refuses us (HTTP 403): stop at once instead of retrying, so a block is not made worse."""


@dataclass
class ClusterIndex:
    """``cluster.idx`` in memory: the SURT key that starts each block and where the block lives."""

    surts: list[str]
    files: list[str]
    offsets: list[int]
    lengths: list[int]

    def __len__(self) -> int:
        return len(self.surts)


def surt_prefix(domain: str) -> str:
    """SURT key of a domain: its labels reversed and comma separated (``bbc.co.uk`` -> ``uk,co,bbc``)."""
    return ",".join(reversed(domain.lower().strip(".").split(".")))


def parse_cluster(lines: Iterable[str]) -> ClusterIndex:
    index = ClusterIndex([], [], [], [])
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 4:
            continue
        index.surts.append(parts[0].split(" ", 1)[0])
        index.files.append(parts[1])
        index.offsets.append(int(parts[2]))
        index.lengths.append(int(parts[3]))
    return index


def domain_range(domain: str) -> tuple[str, str]:
    """(lo, hi): the domain and every subdomain have keys ``lo <= key < hi`` (``)`` and ``,`` sort before ``-``)."""
    prefix = surt_prefix(domain)
    return prefix + ")", prefix + "-"


def host_range(suffix: str) -> tuple[str, str]:
    """(lo, hi) of every subdomain of ``suffix`` (not the suffix itself)."""
    prefix = surt_prefix(suffix)
    return prefix + ",", prefix + "-"


def block_range(index: ClusterIndex, lo: str, hi: str) -> range:
    """Indices of the blocks that can hold keys in ``[lo, hi)``: from the block before the first key at or after lo."""
    first = max(0, bisect_right(index.surts, lo) - 1)
    last = bisect_left(index.surts, hi) - 1
    return range(first, max(first, last) + 1)


def fetch_block(fetch: Fetch, crawl: str, index: ClusterIndex, i: int) -> list[str]:
    """The decompressed lines of block ``i`` (one gzip member per block)."""
    url = f"{DATA_BASE}/cc-index/collections/{crawl}/indexes/{index.files[i]}"
    data = fetch(url, index.offsets[i], index.lengths[i])
    return gzip.decompress(data).decode("utf-8", "replace").splitlines()


def parse_line(line: str) -> tuple[str, dict[str, Any]] | None:
    """(SURT key, JSON fields) of an index line, or None for a malformed one."""
    parts = line.split(" ", 2)
    if len(parts) != 3:
        return None
    try:
        record = json.loads(parts[2])
    except ValueError:
        return None
    return (parts[0], record) if isinstance(record, dict) else None


def usable_url(record: dict[str, Any]) -> str | None:
    """The crawled URL when it is a successful HTML page on http or https of a sane length, else None."""
    url = str(record.get("url", ""))
    mime = str(record.get("mime-detected") or record.get("mime") or "")
    if record.get("status") != "200" or mime not in HTML_MIMES or len(url) > MAX_URL_CHARS or not url.isascii():
        return None
    return url if url.startswith(("http://", "https://")) else None


def lines_in_range(lines: Iterable[str], lo: str, hi: str) -> list[str]:
    """Usable URLs of the index lines whose key is in ``[lo, hi)``."""
    urls = []
    for line in lines:
        parsed = parse_line(line)
        if parsed is None or not lo <= parsed[0] < hi:
            continue
        if (url := usable_url(parsed[1])) is not None:
            urls.append(url)
    return urls


def http_range(url: str, start: int, length: int, attempts: int = 6) -> bytes:
    """One range request with back-off on 429/5xx and transient network errors."""
    request = urllib.request.Request(  # noqa: S310 - fixed https host
        url, headers={"Range": f"bytes={start}-{start + length - 1}", "User-Agent": USER_AGENT}
    )
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:  # noqa: S310
                data: bytes = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise BlockedError(f"HTTP 403 for {url}: the server blocks this address; wait and rerun") from None
            if exc.code not in (429, 500, 502, 503, 504):
                raise LinkFileBenchError(f"HTTP {exc.code} for {url}") from None
            last = exc
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError) as exc:
            last = exc
        else:
            if len(data) != length:
                raise LinkFileBenchError(f"range of {url} returned {len(data)} bytes, expected {length}")
            time.sleep(PAUSE_SECONDS)
            return data
        time.sleep(min(60.0, 2.0**attempt + random.random()))  # noqa: S311 - jitter, not security
    raise LinkFileBenchError(f"giving up on {url}: {last}")


def download(url: str, dest: Path) -> None:
    """Stream ``url`` to ``dest`` (0600, atomic rename)."""
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = dest.with_suffix(dest.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=120) as response, tmp.open("wb") as out:  # noqa: S310
        while chunk := response.read(1 << 20):
            out.write(chunk)
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)


def majestic_candidates(path: Path, rank_limit: int, count: int, seed: str = SEED) -> list[tuple[str, int]]:
    """``count`` (domain, rank) pairs drawn by seeded hash from the first ``rank_limit`` Majestic ranks."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or not {"GlobalRank", "Domain"} <= set(reader.fieldnames):
            raise LinkFileBenchError("the Majestic CSV has no GlobalRank and Domain columns")
        pool = {}
        for row in reader:
            rank = int(row["GlobalRank"])
            domain = row["Domain"].strip().lower()
            if rank <= rank_limit and domain.isascii() and "." in domain:
                pool[domain] = rank
    ordered = sorted(pool, key=lambda d: seeded_key(seed, f"ccdomain|{d}"))
    return [(d, pool[d]) for d in ordered[:count]]


def sample_domain(
    fetch: Fetch, crawl: str, index: ClusterIndex, domain: str, *, seed: str, per_domain: int, blocks: int
) -> tuple[list[str], int]:
    """(URLs, blocks fetched) for one domain: up to ``per_domain`` usable URLs from up to ``blocks`` random blocks."""
    lo, hi = domain_range(domain)
    span = block_range(index, lo, hi)
    chosen = sorted(span, key=lambda i: seeded_key(seed, f"block|{domain}|{i}"))[:blocks]
    urls: set[str] = set()
    for i in sorted(chosen):
        urls.update(lines_in_range(fetch_block(fetch, crawl, index, i), lo, hi))
    ordered = sorted(urls, key=lambda u: seeded_key(seed, f"url|{u}"))
    return ordered[:per_domain], len(chosen)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def sample_platform(
    fetch: Fetch, crawl: str, index: ClusterIndex, suffix: str, *, seed: str, blocks: int, per_host: int
) -> tuple[list[str], dict[str, int]]:
    """URLs on user subdomains of ``suffix`` from ``blocks`` random blocks, at most ``per_host`` per host."""
    lo, hi = host_range(suffix)
    span = block_range(index, lo, hi)
    chosen = sorted(span, key=lambda i: seeded_key(seed, f"pblock|{suffix}|{i}"))[:blocks]
    by_host: dict[str, set[str]] = {}
    for i in sorted(chosen):
        for url in lines_in_range(fetch_block(fetch, crawl, index, i), lo, hi):
            host = host_of(url)
            if host.endswith("." + suffix) and host != "www." + suffix:
                by_host.setdefault(host, set()).add(url)
    urls = []
    for host in sorted(by_host):
        urls += sorted(by_host[host], key=lambda u: seeded_key(seed, f"purl|{u}"))[:per_host]
    return urls, {"blocks_in_range": len(span), "blocks_fetched": len(chosen), "hosts": len(by_host)}


def acquire_commoncrawl(
    layout: Layout,
    *,
    crawl: str = CRAWL,
    domains: int = TOP_DOMAINS,
    candidates: int = CANDIDATES,
    per_domain: int = PER_DOMAIN,
    platform_blocks: int = PLATFORM_BLOCKS,
    per_host: int = PER_HOST,
    seed: str = SEED,
    workers: int = WORKERS,
    fetch: Fetch = http_range,
    fetch_text: Callable[[str, Path], None] = download,
) -> dict[str, Any]:
    """Download ``cluster.idx`` and the terms page, sample the URLs, write ``raw/commoncrawl/<crawl>/``."""
    os.umask(0o077)
    base = layout.raw / "commoncrawl" / crawl
    majestic = layout.raw / "majestic" / "majestic_million.csv"
    if not majestic.is_file():
        raise LinkFileBenchError(f"missing {majestic}; run the dataset acquire first")
    cluster = base / "cluster.idx"
    terms = base / "terms-of-use.html"
    if not cluster.is_file():
        fetch_text(f"{DATA_BASE}/cc-index/collections/{crawl}/indexes/cluster.idx", cluster)
    if not terms.is_file():
        fetch_text(TERMS_URL, terms)
    with cluster.open(encoding="utf-8") as fh:
        index = parse_cluster(fh)
    if len(index) < 1000:
        raise LinkFileBenchError(f"cluster.idx has only {len(index)} blocks")
    lock = threading.Lock()
    stats: Counter[str] = Counter()

    def one(item: tuple[str, int]) -> tuple[str, int, list[str]]:
        domain, rank = item
        try:
            urls, fetched = sample_domain(
                fetch, crawl, index, domain, seed=seed, per_domain=per_domain, blocks=BLOCKS_PER_DOMAIN
            )
        except BlockedError:
            raise
        except LinkFileBenchError:
            with lock:
                stats["domain_fetch_failed"] += 1
            return domain, rank, []
        with lock:
            stats["blocks_fetched"] += fetched
        return domain, rank, urls

    rows: list[dict[str, Any]] = []
    pool = majestic_candidates(majestic, RANK_LIMIT, candidates, seed)
    kept_domains = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for start in range(0, len(pool), BATCH):
            if kept_domains >= domains:
                break
            for domain, rank, urls in executor.map(one, pool[start : start + BATCH]):
                stats["domains_tried"] += 1
                if urls and kept_domains < domains:
                    kept_domains += 1
                    rows += [{"url": u, "cohort": TOP_COHORT, "domain": domain, "rank": rank} for u in urls]
    platforms: dict[str, Any] = {}
    for suffix in PLATFORMS:
        urls, info = sample_platform(fetch, crawl, index, suffix, seed=seed, blocks=platform_blocks, per_host=per_host)
        platforms[suffix] = {
            **info,
            "urls": len(urls),
            "share_of_index_blocks": round(info["blocks_in_range"] / len(index), 6),
        }
        rows += [{"url": u, "cohort": suffix, "domain": host_of(u), "rank": None} for u in urls]
    out = base / "urls.jsonl"
    write_private(out, b"".join((json.dumps(r, sort_keys=True) + "\n").encode() for r in rows))
    manifest = {
        "schema_version": 1,
        "generated_at": now(),
        "crawl": crawl,
        "terms_url": TERMS_URL,
        "terms_sha256": file_sha256(terms),
        "cluster_idx": {"blocks": len(index), "bytes": cluster.stat().st_size, "sha256": file_sha256(cluster)},
        "seed": seed,
        "parameters": {
            "majestic_rank_limit": RANK_LIMIT,
            "candidate_domains": candidates,
            "target_domains": domains,
            "urls_per_domain": per_domain,
            "blocks_per_domain": BLOCKS_PER_DOMAIN,
            "platform_blocks": platform_blocks,
            "urls_per_platform_host": per_host,
            "filter": "HTTP status 200 and an HTML MIME type",
        },
        "top_domain": {"domains_with_urls": kept_domains, "urls": sum(1 for r in rows if r["cohort"] == TOP_COHORT)},
        "platforms": platforms,
        "requests": dict(sorted(stats.items())),
        "urls_sha256": file_sha256(out),
    }
    write_json(base / "manifest.json", manifest)
    return manifest


__all__ = ["acquire_commoncrawl", "domain_range", "host_range", "surt_prefix"]
