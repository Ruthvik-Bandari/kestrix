# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Aggregate probes for the rule round: how often each curated tag occurs in each cohort of dev items.

The raw URLs and files are read on the cluster only. A tag is a coarse property fixed in this file before any
dev result was looked at (a hosting-platform family, a host-shape bucket, the content class of the first bytes of a
file). The report holds, per cohort, the item count and the count of each tag that at least ``MIN_CELL`` items
share. It never holds a URL, host, file name or content. Cohorts come from the levels the shipped rules gave on
dev (stored features of an earlier run), so the tags describe what the rules missed or over-flagged.
"""

from __future__ import annotations

import io
import math
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from kestrix.forensics.analysis import _WSH_API, _wsh_style, html_obfuscation_signals
from kestrix.forensics.ole import parse_ole_directory

from .common import BENIGN, PHISHING, Layout, LinkFileBenchError, now, read_jsonl, write_json
from .features import read_features
from .links import registered_domain
from .metrics import RANK, category
from .sources import GOVDOCS

MIN_CELL = 3
HEAD = 4096
REPORT = "{kind}-probe.json"

# Platforms where anyone can publish a page under a subdomain (curated, public knowledge of abused services).
PLATFORMS = {
    "site_builder": (
        "weebly.com wixsite.com blogspot.com wordpress.com webflow.io godaddysites.com sites.google.com "
        "000webhostapp.com yolasite.com jimdofree.com strikingly.com mystrikingly.com carrd.co square.site "
        "myportfolio.com tumblr.com medium.com notion.site webnode.com"
    ),
    "static_or_cloud_hosting": (
        "github.io gitlab.io netlify.app vercel.app pages.dev workers.dev web.app firebaseapp.com herokuapp.com "
        "glitch.me repl.co onrender.com azurewebsites.net azurestaticapps.net cloudfront.net amazonaws.com "
        "appspot.com r2.dev ipfs.io dweb.link storage.googleapis.com blob.core.windows.net surge.sh fleek.co"
    ),
    "dynamic_dns_or_tunnel": (
        "duckdns.org no-ip.com no-ip.org no-ip.biz ddns.net hopto.org zapto.org serveo.net ngrok.io "
        "ngrok-free.app trycloudflare.com loca.lt myftp.biz sytes.net servebeer.com"
    ),
    "form_or_doc_service": (
        "forms.gle typeform.com jotform.com formstack.com surveymonkey.com canva.com sharepoint.com "
        "1drv.ms dropbox.com docs.google.com drive.google.com"
    ),
}
_PLATFORM_OF = {suffix: family for family, text in PLATFORMS.items() for suffix in text.split()}


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


def platform_family(host: str) -> str | None:
    """The platform family when ``host`` is a user subdomain of a listed platform (not the platform's own root)."""
    for suffix, family in _PLATFORM_OF.items():
        if host.endswith("." + suffix) and host not in (suffix, "www." + suffix):
            return family
    return None


def link_tags(url: str) -> set[str]:
    """Host-shape and hosting tags of one URL (never the URL itself)."""
    parts = urlsplit(url if "://" in url else "//" + url)
    host = (parts.hostname or "").lower().rstrip(".")
    tags: set[str] = set()
    registered = registered_domain(host)
    label = registered.split(".", 1)[0]
    labels = host.split(".")
    if family := platform_family(host):
        tags.add(f"platform:{family}")
    for name, cond in (
        ("label_hyphens_ge1", label.count("-") >= 1),
        ("label_hyphens_ge2", label.count("-") >= 2),
        ("label_digits_ge3", sum(c.isdigit() for c in label) >= 3),
        ("label_len_ge20", len(label) >= 20),
        ("host_len_ge35", len(host) >= 35),
        ("dots_ge3", host.count(".") >= 3),
        ("label_entropy_ge3_5_len_ge10", len(label) >= 10 and _entropy(label) >= 3.5),
        ("label_numeric_only", label.isdigit()),
        ("subdomain_digits_ge3", sum(c.isdigit() for part in labels[:-2] for c in part) >= 3),
        ("tld_len_ge5", len(labels[-1]) >= 5),
        ("path_deep_ge3", parts.path.strip("/").count("/") >= 2),
        ("query_has_url", "http" in parts.query.lower()),
        ("path_has_ext_php_html_asp", parts.path.lower().endswith((".php", ".html", ".htm", ".asp", ".aspx", ".jsp"))),
        (
            "path_has_ext_exe_zip_apk",
            parts.path.lower().endswith((".exe", ".zip", ".apk", ".msi", ".rar", ".scr", ".jar")),
        ),
        ("percent_encoding_ge3", url.count("%") >= 3),
        ("at_in_query_or_path", "@" in parts.path or "@" in parts.query),
        ("double_slash_in_path", "//" in parts.path),
    ):
        if cond:
            tags.add(name)
    return tags


def _add(cohorts: dict[str, Counter[str]], sizes: Counter[str], names: list[str], tags: set[str]) -> None:
    for name in names:
        sizes[name] += 1
        cohorts[name].update(tags)


def _finish(cohorts: dict[str, Counter[str]], sizes: Counter[str]) -> dict[str, Any]:
    return {
        name: {
            "n": sizes[name],
            "tags": {t: c for t, c in sorted(cohorts[name].items()) if c >= MIN_CELL},
        }
        for name in sorted(sizes)
    }


def probe_links(layout: Layout) -> dict[str, Any]:
    dev = {r["id"]: r for r in read_features(layout, "dev")}
    cohorts: dict[str, Counter[str]] = defaultdict(Counter)
    sizes: Counter[str] = Counter()
    for shard in range(layout.shards):
        for item in read_jsonl(layout.raw_shard(shard)):
            row = dev.get(item["id"])
            if row is None:
                continue
            kind = "phishing" if row["label"] == PHISHING else f"benign_{row['source']}"
            names = [kind]
            if row["label"] == PHISHING and RANK[row["level"]] < 2:
                names.append("phishing_missed_below_medium")
            if row["https"] and not row["path"] and not row["query"]:
                names.append(f"{kind}_bare_https")
                if row["label"] == PHISHING and RANK[row["level"]] < 2:
                    names.append("phishing_bare_https_missed_below_medium")
            _add(cohorts, sizes, names, link_tags(item["url"]))
    return _finish(cohorts, sizes)


def _head_class(head: bytes, type_id: str) -> set[str]:
    lowered = head[:HEAD].lower()
    tags = {f"type:{type_id}"}
    for name, cond in (
        ("head_rtf", head.startswith(b"{\\rtf")),
        ("head_html", b"<html" in lowered or b"<!doctype html" in lowered),
        ("head_xml", head.lstrip().startswith(b"<?xml")),
        ("head_utf16_bom", head.startswith((b"\xff\xfe", b"\xfe\xff"))),
        ("head_postscript", head.startswith(b"%!")),
        ("head_mime_or_mail", b"mime-version:" in lowered or head.startswith(b"From ")),
        ("head_pdf_after_1k", b"%PDF-" in head[1024:] and b"%PDF-" not in head[:1024]),
        (
            "head_mostly_ascii",
            bool(head) and sum(32 <= b < 127 or b in (9, 10, 13) for b in head[:HEAD]) / len(head[:HEAD]) > 0.95,
        ),
        ("head_has_null", b"\x00" in head[:HEAD]),
    ):
        if cond:
            tags.add(name)
    return tags


HTML_EXT = frozenset({"html", "htm", "xhtml", "shtml", "svg"})
OLE_NAMES = ("VBA", "Macros", "_VBA_PROJECT", "_VBA_PROJECT_CUR", "PROJECT", "PROJECTwm")


def _sample(data: bytes) -> bytes:
    """The first and last 64 KiB, like the analyzer's header and tail samples."""
    return data if len(data) <= 131072 else data[:65536] + data[-65536:]


def content_tags(data: bytes, ext: str, type_id: str) -> set[str]:
    """Tags for the content rules of the gaps round: HTML signals, Windows Script Host JavaScript, OLE macro names."""
    tags: set[str] = set()
    if ext in HTML_EXT and type_id in ("text", "unknown"):
        signals = html_obfuscation_signals(_sample(data).decode("latin-1"))
        tags |= {f"sig:{name}" for name in signals} | {f"sigset:{'+'.join(sorted(signals)) or 'none'}"}
    elif ext == "js":
        text = _sample(data).decode("latin-1")
        tags.add("js_wsh" if _wsh_style(text) else "js_plain")
        if _WSH_API.search(text):
            tags.add("js_wsh_api")
    elif type_id == "ole2":
        result = parse_ole_directory(io.BytesIO(data), len(data))
        tags.add("ole_vba" if result.has_vba else "ole_readable_no_vba" if result.readable else "ole_unreadable")
        tags |= {f"ole_has:{n}" for n in OLE_NAMES if n in result.names}
    return tags


def probe_files(layout: Layout, raw: Path, meta: dict[str, dict[str, Any]], threads: list[str]) -> dict[str, Any]:
    dev = {r["id"]: r for r in read_features(layout, "dev") if r["source"] == GOVDOCS}
    cohorts: dict[str, Counter[str]] = defaultdict(Counter)
    sizes: Counter[str] = Counter()
    for shard, name in enumerate(threads):
        wanted = {
            m["member"]: i for i, m in meta.items() if m["source"] == GOVDOCS and m["shard"] == shard and i in dev
        }
        path = raw / GOVDOCS / name
        if not path.is_file():
            raise LinkFileBenchError(f"{path} is missing; run acquire first")
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                item_id = wanted.get(info.filename)
                if item_id is None:
                    continue
                row = dev[item_id]
                alarm = max((RANK[s] for f, s in row["findings"] if category(f) == "security"), default=0)
                names = ["govdocs_all"]
                if alarm >= 1:
                    names.append("alarm_low_or_higher")
                if alarm >= 2:
                    names.append("alarm_medium_or_higher")
                with archive.open(info) as fh:
                    head = fh.read(65536)
                    rest = fh.read() if row["type"] == "ole2" or row["ext"] in HTML_EXT | {"js"} else b""
                extra = content_tags(head + rest, row["ext"], row["type"])
                _add(cohorts, sizes, names, _head_class(head, row["type"]) | {f"ext:{row['ext']}"} | extra)
    return _finish(cohorts, sizes)


def run_probe(layout: Layout, raw: Path, kind: str, meta: dict[str, dict[str, Any]], threads: list[str]) -> Path:
    body = probe_links(layout) if kind == "link" else probe_files(layout, raw, meta, threads)
    out = layout.reports / REPORT.format(kind=kind)
    write_json(
        out,
        {
            "schema_version": 1,
            "kind": kind,
            "split": "dev",
            "generated_at": now(),
            "min_cell": MIN_CELL,
            "cohorts": body,
        },
    )
    return out


__all__ = ["BENIGN", "link_tags", "run_probe"]
