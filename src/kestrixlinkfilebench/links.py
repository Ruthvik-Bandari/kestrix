# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Link benchmark data: read the URL lists, deduplicate, label and group; run ``analyze_url`` per URL.

URLs are text only: nothing here fetches, resolves or visits one. Outputs under ``<root>/link`` (0600/0700):

* ``work/raw/shard-NN.jsonl``: ``{id, url}`` per kept URL, sharded by id (cluster only);
* ``work/meta.jsonl``: ``{id, source, subset, label, year, group, shard}``;
* ``reports/build.json``: counts only.

PhiUSIIL labels 1 = legitimate, 0 = phishing: they are inverted here (``read_phiusiil``, tested). Majestic
hosts become host-root URLs (``https://domain/``, half of them with ``www.``) and are benign by assumption:
they are popular sites, some of which may host abuse on subdomains or paths this list cannot see.
URLs the analyzer rejects are dropped with a reason. Exact duplicates share the lower-cased scheme, host and
path plus query; near duplicates share the host without ``www.`` and the path (query ignored). A near-duplicate
key that carries both labels is dropped from both. The split group is a hash of the registered domain.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
import zipfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from kestrix.core.errors import Rejected
from kestrix.forensics.url import analyze_url

from .common import (
    BENIGN,
    PHISHING,
    SEED,
    Layout,
    LinkFileBenchError,
    now,
    read_jsonl,
    seeded_key,
    write_json,
    write_jsonl,
)
from .sources import MAJESTIC, PHIUSIIL

csv.field_size_limit(10**8)

_SCHEME = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://")
# Second-level labels under a two-letter country code (co.uk, com.au, ac.jp): grouped as three labels.
_SECOND = frozenset(
    {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "nom", "mil", "sch", "ltd", "plc"}
)
LEVELS = ("none", "low", "medium", "high")


def read_phiusiil(path: Path, limit: int | None = None) -> Iterator[tuple[str, str]]:
    """(url, label) per CSV row of the PhiUSIIL zip; label 1 (legitimate) becomes benign, 0 becomes phishing."""
    with zipfile.ZipFile(path) as archive:
        names = [i.filename for i in archive.infolist() if i.filename.lower().endswith(".csv")]
        if len(names) != 1:
            raise LinkFileBenchError(f"{path.name} should hold exactly one CSV, found {len(names)}")
        with archive.open(names[0]) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
            if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
                raise LinkFileBenchError("the PhiUSIIL CSV has no URL and label columns")
            for n, row in enumerate(reader):
                if limit is not None and n >= limit:
                    return
                label = row["label"].strip()
                if label not in ("0", "1"):
                    raise LinkFileBenchError(f"unexpected PhiUSIIL label {label!r}")
                yield row["URL"], BENIGN if label == "1" else PHISHING


def majestic_urls(path: Path, count: int, seed: str = SEED) -> list[str]:
    """``count`` host-root URLs from the Majestic Million, chosen by seeded hash of the domain."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "Domain" not in reader.fieldnames:
            raise LinkFileBenchError("the Majestic CSV has no Domain column")
        domains = [row["Domain"].strip().lower() for row in reader if row["Domain"].strip()]
    chosen = sorted(set(domains), key=lambda d: seeded_key(seed, d))[:count]
    return [("https://www." if seeded_key(seed, f"www|{d}")[0] in "01234567" else "https://") + d + "/" for d in chosen]


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url if _SCHEME.match(url) else "//" + url)
        return (parts.hostname or "").lower().rstrip(".") or None
    except ValueError:
        return None


def registered_domain(host: str) -> str:
    """Offline estimate of the registered domain, used only to group URLs for the split.

    The last two labels, or three under a two-letter country code with a common second level (``co.uk``).
    It is coarser than the Public Suffix List for shared hosting (every ``*.blogspot.com`` is one group),
    which is the safe direction: a coarser group can only keep more items together.
    """
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    take = 3 if len(labels[-1]) == 2 and labels[-2] in _SECOND else 2
    return ".".join(labels[-take:])


def group_of(host: str) -> str:
    """Split group of a host: a hash of its registered domain, so no host name is stored with the features."""
    return "d" + hashlib.sha256(registered_domain(host).encode()).hexdigest()[:16]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def exact_key(url: str) -> str:
    parts = urlsplit(url if _SCHEME.match(url) else "//" + url)
    scheme = parts.scheme.lower()
    path = parts.path if parts.path != "/" else ""
    return f"{scheme}|{(parts.hostname or '').lower()}|{path}|{parts.query}"


def near_key(url: str) -> str:
    parts = urlsplit(url if _SCHEME.match(url) else "//" + url)
    host = (parts.hostname or "").lower().rstrip(".").removeprefix("www.")
    return f"{host}|{parts.path.rstrip('/')}"


def url_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:24]


Candidate = tuple[str, str, str, str]  # (source, subset, label, url)


def _filter(candidates: list[Candidate], dropped: Counter[str]) -> list[tuple[str, str, str, str, str]]:
    """Drop URLs without a host and URLs the analyzer rejects; append the near-duplicate key."""
    valid = []
    for source, subset, label, url in candidates:
        cell = f"{source}/{label}"
        if not url or host_of(url) is None:
            dropped[f"{cell}|unparsable"] += 1
            continue
        try:
            analyze_url(url)
        except Rejected as exc:
            dropped[f"{cell}|{exc.reason.value}"] += 1
            continue
        valid.append((source, subset, label, url, near_key(url)))
    return valid


def _dedupe(
    valid: list[tuple[str, str, str, str, str]], dropped: Counter[str], shards: int, seed: str
) -> list[dict[str, Any]]:
    """Keep the first of each exact and near duplicate; drop every URL whose near key carries both labels."""
    labels_of: dict[str, set[str]] = {}
    for _, _, label, _, near in valid:
        labels_of.setdefault(near, set()).add(label)
    kept: list[dict[str, Any]] = []
    seen_exact: set[str] = set()
    seen_near: set[str] = set()
    for source, subset, label, url, near in sorted(valid, key=lambda c: (c[0] != PHIUSIIL, seeded_key(seed, c[3]))):
        cell = f"{source}/{label}"
        if len(labels_of[near]) > 1:
            dropped[f"{cell}|conflicting_label"] += 1
        elif (key := exact_key(url)) in seen_exact:
            dropped[f"{cell}|duplicate_exact"] += 1
        elif near in seen_near:
            dropped[f"{cell}|duplicate_near"] += 1
        else:
            seen_exact.add(key)
            seen_near.add(near)
            ident = url_id(url)
            kept.append(
                {
                    "id": ident,
                    "source": source,
                    "subset": subset,
                    "label": label,
                    "year": None,
                    "group": group_of(host_of(url) or ""),
                    "shard": int(ident[:8], 16) % shards,
                    "url": url,
                }
            )
    return kept


def build_links(
    raw: Path, layout: Layout, majestic: int = 30_000, limit: int | None = None, seed: str = SEED
) -> dict[str, Any]:
    """Read, filter, deduplicate and group the URLs; write ``work/`` and ``reports/build.json``."""
    phi_path = raw / PHIUSIIL / "phiusiil.zip"
    maj_path = raw / MAJESTIC / "majestic_million.csv"
    for path in (phi_path, maj_path):
        if not path.is_file():
            raise LinkFileBenchError(f"missing input {path}; run acquire on the transfer node first")
    candidates: list[Candidate] = [
        (PHIUSIIL, label, label, url.strip()) for url, label in read_phiusiil(phi_path, limit)
    ]
    raw_labels = Counter(label for _, label, _, _ in candidates)
    wanted = majestic if limit is None else min(majestic, limit)
    candidates += [(MAJESTIC, "root", BENIGN, url) for url in majestic_urls(maj_path, wanted, seed)]
    read = Counter(f"{source}/{label}" for source, _, label, _ in candidates)
    dropped: Counter[str] = Counter()
    kept = _dedupe(_filter(candidates, dropped), dropped, layout.shards, seed)
    if len({k["id"] for k in kept}) != len(kept):
        raise LinkFileBenchError("URL id collision")
    kept.sort(key=lambda k: k["id"])
    for shard in range(layout.shards):
        write_jsonl(layout.raw_shard(shard), ({"id": k["id"], "url": k["url"]} for k in kept if k["shard"] == shard))
    write_jsonl(layout.meta, ({k: v for k, v in item.items() if k != "url"} for item in kept))
    report = {
        "schema_version": 1,
        "kind": "link",
        "generated_at": now(),
        "seed": seed,
        "phiusiil_raw_label_counts": {"1_legitimate_to_benign": raw_labels[BENIGN], "0_phishing": raw_labels[PHISHING]},
        "read": dict(sorted(read.items())),
        "dropped": dict(sorted(dropped.items())),
        "kept": dict(sorted(Counter(f"{k['source']}/{k['label']}" for k in kept).items())),
        "kept_total": len(kept),
        "groups": len({k["group"] for k in kept}),
        "majestic": {"hosts_requested": wanted, "url_form": "https://[www.]domain/ (host root only)"},
    }
    write_json(layout.reports / "build.json", report)
    return report


def read_meta(layout: Layout) -> list[dict[str, Any]]:
    if not layout.meta.is_file():
        raise LinkFileBenchError(f"{layout.meta} is missing; run build first")
    return list(read_jsonl(layout.meta))


def link_row(url: str) -> dict[str, Any]:
    """Analyze one URL offline and return the stored fields: findings, level, score and shape counts, no URL."""
    report = analyze_url(url)
    parts = urlsplit(url if _SCHEME.match(url) else "//" + url)
    host = report.host
    return {
        "level": report.level,
        "score": report.score,
        "findings": [[f.id, f.severity] for f in report.findings],
        "len": len(url),
        "path": int(parts.path not in ("", "/")),
        "query": int(bool(parts.query)),
        "depth": parts.path.strip("/").count("/") + 1 if parts.path.strip("/") else 0,
        "dots": host.count("."),
        "hyph": host.count("-"),
        "digits": sum(ch.isdigit() for ch in host),
        "https": int(parts.scheme == "https"),
        "tld": host.rsplit(".", 1)[-1] if not _is_ip(host) else "ip",
    }


def run_link_shard(
    layout: Layout,
    shard: int,
    meta: dict[str, dict[str, Any]],
    split_of: dict[str, str],
    splits: tuple[str, ...],
) -> dict[str, Any]:
    """Analyze every URL of ``shard`` in ``splits``; a split left out is neither analyzed nor written."""
    from .features import write_shard

    rows: dict[str, list[dict[str, Any]]] = {side: [] for side in splits}
    errors: Counter[str] = Counter()
    path = layout.raw_shard(shard)
    if not path.is_file():
        raise LinkFileBenchError(f"{path} is missing; run build first")
    for item in read_jsonl(path):
        side = split_of[item["id"]]
        if side not in splits:
            continue
        info = meta[item["id"]]
        try:
            fields = link_row(item["url"])
        except Rejected as exc:
            errors[exc.reason.value] += 1
            continue
        except Exception:
            errors["analyzer_error"] += 1
            continue
        rows[side].append(
            {**{k: info[k] for k in ("id", "source", "subset", "label", "year", "group")}, "split": side, **fields}
        )
    return write_shard(layout, shard, rows, errors)
