# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Aggregate probes for the rule rounds: how often each tag occurs in each cohort of dev messages.

The raw messages are read on the cluster only. A tag is a coarse property of one message (a bucketed link
count, an attachment extension from a fixed list, a curated candidate term, which mailing-list headers it
has, which reply-to relation holds). The report holds, per cohort, the message count and the count of each
tag that at least ``MIN_CELL`` messages share. It never holds a body, subject, address, host or message id.
Cohorts come from the verdicts the shipped rules gave on dev (stored features of an earlier run).
"""

from __future__ import annotations

import base64
import email
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlsplit

from kestrix.mail.analyzers import (
    _EMAIL_IN_TEXT,
    _is_ip,
    _looks_like_domain,
    _looks_like_tracking,
    _shown_host,
    aligned,
    org_domain,
)
from kestrix.mail.parse import ParsedMessage, normalize_domain, parse_message

from .common import Layout, now, read_jsonl, write_json
from .features import read_features
from .metrics import CONTENT, kept_findings, restricted_verdict

MIN_CELL = 3
MAX_TEXT = 20_000
REPORT = "mail-probe.json"

# Curated candidate wording (lower case), written before looking at any dev message.
SPAM_STRONG = {
    "viagra": r"viagra|cialis|levitra|xanax|valium|phentermine",
    "mortgage": r"mortgage|refinanc",
    "act_now": r"act now|order now|call now|apply now|buy now|click here now",
    "limited_time": r"limited time|while supplies last|offer expires|expires soon",
    "free_money": r"free money|cash bonus|free cash|easy money|extra income|make money|earn \$|earn money",
    "credit_offer": r"credit card offers?|pre-?approved|low interest|lowest rates?|bad credit|debt consolidation",
    "work_home": r"work (?:from|at) home|be your own boss|home[- ]based business",
    "weight_loss": r"lose weight|weight loss|diet pills?",
    "enlarge": r"enlarge|penis|erectile",
    "not_spam": r"this is not spam|not (?:a )?spam|remove me|to be removed|to unsubscribe|opt[- ]out",
    "free_offer": r"100% free|absolutely free|free (?:gift|trial|quote|membership|sample)|no obligation|risk[- ]free",
    "guarantee": r"100% guaranteed|money[- ]back guarantee|satisfaction guaranteed",
    "pct_off": r"\d{1,2}% off|save up to|save \$?\d+|discount",
    "bulk_mail": r"bulk e-?mail|mailing list.{0,30}(?:million|\d{3,})|million (?:e-?mail|addresses)",
    "investment": r"hot stock|penny stock|stock alert|investment opportunity|financial freedom",
    "dollar_amount": r"\$\d{1,3}(?:,\d{3})+|\$\d{4,}",
    "dear_friend": r"dear (?:friend|sir|madam|valued customer|homeowner)",
    "diploma": r"online degree|university diploma|no exams",
    "pharmacy": r"online pharmacy|prescription|no prescription|pharmacy",
    "adult": r"\bxxx\b|adult (?:site|content|dvd)|hot (?:girls|teens)|live cams?",
    "congratulations": r"congratulations",
    "visit_site": r"visit (?:our|my) (?:web ?site|site)|click (?:here|below) to",
}
SPAM_WEAK = {"unsubscribe": r"unsubscribe", "free": r"\bfree\b", "click": r"\bclick\b", "offer": r"\boffer\b"}
PHISH_TERMS = {
    "password": r"password",
    "account": r"\baccount\b",
    "verify": r"verify|validate|confirm",
    "security": r"security",
    "update": r"update",
    "bank": r"\bbank\b",
    "suspend": r"suspend|locked|restricted|limited",
    "login": r"log-?in|sign-?in",
    "click": r"click",
    "invoice": r"invoice|payment|receipt",
    "attached": r"attached|attachment",
    "document": r"document|shared with you|sharepoint|onedrive|docusign",
}
FREEMAIL = frozenset(
    [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "aol.com",
        "live.com",
        "msn.com",
        "mail.com",
        "gmx.com",
        "protonmail.com",
        "icloud.com",
    ]
)
FREE_HOSTING = (
    "docs.google.com",
    "sites.google.com",
    "drive.google.com",
    "storage.googleapis.com",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "firebaseapp.com",
    "web.app",
    "github.io",
    "000webhostapp.com",
    "herokuapp.com",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "sharepoint.com",
    "dropbox.com",
    "forms.gle",
    "typeform.com",
    "jotform.com",
    "myfreesites.net",
    "godaddysites.com",
    "yolasite.com",
)
# Spam-offer candidates by tier: tier 1 words almost never appear in ham on a first look, tier 2 words need company.
SPAM_TIER1 = (
    r"mortgage|refinanc|credit card offers?|pre-?approved|bad credit|debt consolidation|lowest rates?",
    r"lose weight|weight loss|diet pills?|penis|enlarge",
    r"work (?:from|at) home|be your own boss|home[- ]based business",
    r"100% guaranteed|money[- ]back guarantee|satisfaction guaranteed",
    r"free money|cash bonus|free cash|easy money|extra income|make money|earn \$|earn money",
    r"bulk e-?mail|million (?:e-?mail|addresses)|hot stock|penny stock|stock alert|investment opportunity",
    r"online pharmacy|no prescription|\bxxx\b|live cams?",
)
SPAM_TIER2 = (
    r"act now|order now|call now|apply now",
    r"limited time|while supplies last|offer expires",
    r"100% free|absolutely free|free (?:gift|trial|quote|membership|sample)|no obligation|risk[- ]free",
    r"\d{1,2}% off|save up to|save \$?\d+",
    r"\$\d{1,3}(?:,\d{3})+|\$\d{4,}",
    r"dear (?:friend|sir|madam|valued customer|homeowner)",
    r"visit (?:our|my) (?:web ?site|site)|click (?:here|below) to",
    r"viagra|cialis|levitra|xanax|valium|phentermine",
    r"congratulations",
    r"unsubscribe|remove me|to be removed|opt[- ]out",
)
ATTACHMENT_EXTENSIONS = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "rtf",
        "csv",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "zip",
        "rar",
        "7z",
        "html",
        "htm",
        "svg",
        "exe",
        "scr",
        "js",
        "vbs",
        "iso",
        "img",
        "docm",
        "xlsm",
        "eml",
        "ics",
    ]
)
_LIST_DOMAIN_ID = re.compile(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}")
_LIST_DOMAIN_URL = re.compile(r"(?:@|//)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})")
LIST_HEADERS = (
    "list-id",
    "list-post",
    "list-unsubscribe",
    "list-subscribe",
    "list-help",
    "list-archive",
    "x-mailing-list",
    "mailing-list",
    "x-list",
    "sender",
    "errors-to",
    "x-beenthere",
)


def _bucket(value: int, edges: tuple[int, ...]) -> str:
    for edge in edges:
        if value <= edge:
            return str(edge)
    return f"{edges[-1]}+"


def _list_domains(headers: Any) -> dict[str, set[str]]:
    """Organizational domains named by each list-style header (names only, never stored)."""
    out: dict[str, set[str]] = {}
    for name in LIST_HEADERS:
        value = headers.get(name)
        if not value:
            continue
        text = str(value).lower()[:600]
        found = [text_match for text_match in _LIST_DOMAIN_URL.findall(text)]
        if name in ("list-id", "x-mailing-list", "mailing-list", "x-list"):
            found += _LIST_DOMAIN_ID.findall(text)
        out[name] = {org_domain(d) for d in found}
    return out


def _link_tags(parsed: ParsedMessage) -> set[str]:
    tags: set[str] = set()
    web: list[tuple[str, str]] = []
    for link in parsed.links:
        try:
            parts = urlsplit(link.href.strip())
            host = parts.hostname
        except ValueError:
            continue
        if parts.scheme.lower() in ("http", "https") and host:
            web.append((parts.scheme.lower(), host.lower()))
    tags.add(f"links:{_bucket(len(parsed.links), (0, 1, 2, 5, 20))}")
    hosts = {h for _, h in web}
    tags.add(f"link_hosts:{_bucket(len(hosts), (0, 1, 2, 5))}")
    if web:
        schemes = {s for s, _ in web}
        tags.add("scheme:" + ("https" if schemes == {"https"} else "http" if schemes == {"http"} else "mixed"))
        sender = parsed.from_.domain if parsed.from_ else None
        foreign = [h for h in hosts if sender is None or not aligned(h, sender)]
        tags.add("links_all_foreign" if len(foreign) == len(hosts) else "links_some_own")
        for suffix in FREE_HOSTING:
            if any(h == suffix or h.endswith("." + suffix) for h in hosts):
                tags.add(f"freehost:{suffix}")
                tags.add("freehost:any")
    ips = [h for h in hosts if _is_ip(h)]
    if ips:
        kinds = set()
        for host in ips:
            try:
                addr = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                kinds.add("obfuscated")
                continue
            kinds.add(
                "private" if addr.is_private and not addr.is_loopback else "loopback" if addr.is_loopback else "public"
            )
        tags.update(f"ip:{k}" for k in kinds)
        tags.add("ip:only_private" if kinds <= {"private", "loopback"} else "ip:has_public")
    if any("." not in h and not _is_ip(h) for h in hosts):
        tags.add("host:single_label")
    return tags


def _display_name_tags(parsed: ParsedMessage, domains: dict[str, set[str]]) -> set[str]:
    """Anatomy of a display name that shows another address or domain (mirrors the analyzer's own reading)."""
    sender = parsed.from_
    if sender is None or not sender.display_name:
        return set()
    lowered = sender.display_name.lower()
    emails = [m.group(1) for m in _EMAIL_IN_TEXT.finditer(lowered)]
    named = list(emails) + [
        host
        for token in lowered.replace(",", " ").split()
        if "@" not in token and (host := _looks_like_domain(token.strip("()[]<>\"'"), explicit=False))
    ]
    foreign = {normalize_domain(n)[0] for n in named} - {""}
    foreign = {n for n in foreign if not aligned(n, sender.domain)}
    if not foreign:
        return set()
    orgs = {org_domain(n) for n in foreign}
    tags = {"dn:foreign", "dn:email" if emails else "dn:bare_domain"}
    tags.add("dn:just_domain" if lowered.strip(" \"'()<>") in foreign else "dn:with_words")
    tags.add(f"dn:words:{min(len(lowered.split()), 4)}")
    tld = sorted(foreign)[0].rsplit(".", 1)[-1]
    tags.add(f"dn:tld:{tld if len(tld) <= 3 else 'long'}")
    link_orgs = set()
    for link in parsed.links:
        try:
            host = urlsplit(link.href.strip()).hostname
        except ValueError:
            continue
        if host:
            link_orgs.add(org_domain(host.lower()))
    if orgs & link_orgs:
        tags.add("dn:eq_link_any")
    if link_orgs and link_orgs <= orgs:
        tags.add("dn:eq_link_all")
    if not link_orgs:
        tags.add("dn:no_links")
    local = sender.address.rsplit("@", 1)[0].lower()
    if f"{local}@" in lowered:
        tags.add("dn:same_local")
    if any(orgs & found for found in domains.values()):
        tags.add("dn:eq_list_header")
    if any(orgs & {org_domain(r.domain)} for r in parsed.reply_to):
        tags.add("dn:eq_reply_to")
    if parsed.return_path and org_domain(parsed.return_path.domain) in orgs:
        tags.add("dn:eq_return_path")
    if parsed.sender and org_domain(parsed.sender.domain) in orgs:
        tags.add("dn:eq_sender_header")
    mid = (
        parsed.message_id.rsplit("@", 1)[-1].strip("<>").lower()
        if parsed.message_id and "@" in parsed.message_id
        else ""
    )
    if mid and org_domain(mid) in orgs:
        tags.add("dn:eq_message_id")
    return tags


def _mismatch_tags(parsed: ParsedMessage, domains: dict[str, set[str]]) -> set[str]:
    """Anatomy of links whose visible text names another site than the destination."""
    tags: set[str] = set()
    sender = parsed.from_.domain if parsed.from_ else None
    reply = {org_domain(r.domain) for r in parsed.reply_to}
    listed = set().union(*domains.values()) if domains else set()
    for link in parsed.links:
        shown = _shown_host(link)
        try:
            parts = urlsplit(link.href.strip())
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if shown is None or not host or aligned(shown, host) or (sender and aligned(shown, sender)):
            continue
        tags.add("thm:any")
        if _looks_like_tracking(host, parts.path):
            tags.add("thm:tracking_host")
        if parts.scheme.lower() == "https":
            tags.add("thm:href_https")
        for name, orgs in (("list", listed), ("reply_to", reply)):
            if org_domain(shown) in orgs:
                tags.add(f"thm:shown_eq_{name}")
            if org_domain(host) in orgs:
                tags.add(f"thm:href_eq_{name}")
    return tags


def _wording_tags(text: str) -> set[str]:
    tier1 = {f"t1:{i}" for i, p in enumerate(SPAM_TIER1) if re.search(p, text)}
    tier2 = {f"t2:{i}" for i, p in enumerate(SPAM_TIER2) if re.search(p, text)}
    tags = tier1 | tier2
    tags.add(f"t1_distinct:{min(len(tier1), 2)}")
    tags.add(f"t2_distinct:{min(len(tier2), 4)}")
    for k in (2, 3, 4):
        if tier1 or len(tier2) >= k:
            tags.add(f"t1_or_t2_ge{k}")
    return tags


def _structure_tags(parsed: ParsedMessage, raw: Any) -> set[str]:
    """Shape of the message: MIME layout, text length, attachments, sender kind."""
    tags: set[str] = set()
    ctypes = {part.get_content_type() for part in raw.walk()}
    tags.add(f"ctype:{raw.get_content_maintype()}/{raw.get_content_subtype()}")
    tags.add(f"cte:{str(raw.get('content-transfer-encoding', 'none')).strip().lower()[:12]}")
    tags.add("has_html" if "text/html" in ctypes else "no_html")
    tags.add("has_plain" if "text/plain" in ctypes else "no_plain")
    chars = sum(len(t) for t in parsed.texts)
    tags.add(f"text_chars:{_bucket(chars, (0, 200, 1000, 5000))}")
    tags.add(f"attachments:{_bucket(len(parsed.attachments), (0, 1, 2))}")
    if chars == 0 and parsed.attachments:
        tags.add("combo:empty_text_attachment")
    if chars == 0 and parsed.links:
        tags.add("combo:empty_text_link")
    if chars <= 200 and parsed.links:
        tags.add("combo:tiny_text_link")
    if chars <= 200 and parsed.attachments:
        tags.add("combo:tiny_text_attachment")
    for att in parsed.attachments:
        name = att.filename or ""
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else "none"
        tags.add(f"att_ext:{ext if ext in ATTACHMENT_EXTENSIONS or ext == 'none' else 'other'}")
    if parsed.from_:
        tags.add("from_freemail" if parsed.from_.domain in FREEMAIL else "from_other")
        tags.add("display_name" if parsed.from_.display_name else "no_display_name")
    if not parsed.subject:
        tags.add("subject_missing")
    if parsed.reply_to:
        tags.add("reply_to_present")
    return tags


def _reply_tags(parsed: ParsedMessage, raw: Any, domains: dict[str, set[str]]) -> set[str]:
    """Which mailing-list headers exist and what a foreign Reply-To matches."""
    tags = {f"hdr:{name}" for name in LIST_HEADERS if raw.get(name)}
    prec = str(raw.get("precedence", "")).strip().lower()
    if prec:
        tags.add(f"hdr:precedence-{prec if prec in ('list', 'bulk', 'junk') else 'other'}")
    sender = parsed.from_.domain if parsed.from_ else ""
    orgs = {org_domain(r.domain) for r in parsed.reply_to if not aligned(r.domain, sender)}
    if orgs:
        tags.add("rt_foreign")
        tags.update(f"rt_eq:{name}" for name, found in domains.items() if orgs & found)
        if any(orgs & found for found in domains.values()):
            tags.add("rt_eq:any_list_header")
        if parsed.return_path and org_domain(parsed.return_path.domain) in orgs:
            tags.add("rt_eq:return-path")
        if len(orgs) > 1:
            tags.add("rt_multi_domain")
    return tags


def message_tags(data: bytes) -> set[str]:
    """Coarse, non-identifying properties of one message."""
    parsed = parse_message(data)
    raw = email.message_from_bytes(data[:200_000])
    tags = _link_tags(parsed) | _structure_tags(parsed, raw)
    text = " ".join([parsed.subject or "", *parsed.texts])[:MAX_TEXT].lower()
    strong = {name for name, pattern in SPAM_STRONG.items() if re.search(pattern, text)}
    weak = {name for name, pattern in SPAM_WEAK.items() if re.search(pattern, text)}
    tags.update(f"sp:{n}" for n in strong | weak)
    tags.add(f"sp_strong_distinct:{min(len(strong), 4)}")
    tags.add(f"sp_all_distinct:{min(len(strong | weak), 5)}")
    tags.update(f"ph:{n}" for n, pattern in PHISH_TERMS.items() if re.search(pattern, text))
    tags |= _wording_tags(text)
    domains = _list_domains(raw)
    return (
        tags | _reply_tags(parsed, raw, domains) | _display_name_tags(parsed, domains) | _mismatch_tags(parsed, domains)
    )


def cohorts_of(row: dict[str, Any]) -> list[str]:
    """Cohort names a dev row belongs to, from the shipped rules' content-only verdict on it."""
    findings = kept_findings(row, CONTENT)
    verdict = restricted_verdict(findings)[0]
    flagged = verdict in ("suspicious", "malicious")
    ids = {f[0] for f in findings}
    label, source = row["label"], row["source"]
    out: list[str] = []
    if label == "phishing":
        out.append("phishing")
        out.append("phishing_flagged" if flagged else "phishing_missed")
        if not findings:
            out.append("phishing_no_finding")
        elif not flagged:
            out.append("phishing_missed_with_findings")
    elif label == "spam":
        out.append("spam")
        out.append("spam_flagged" if flagged else "spam_missed")
        if not findings:
            out.append("spam_no_finding")
    elif source == "spamassassin":
        out.append("ham_sa")
        if "hard_ham" in row["subset"]:
            out.append("ham_sa_hard")
        if flagged:
            out.append("ham_sa_flagged")
        if verdict == "malicious":
            out.append("ham_sa_malicious")
        if "mail.sender.reply_to_mismatch" in ids:
            out.append("ham_sa_reply_to_mismatch")
    elif source == "enron":
        out.append("ham_enron")
        if flagged:
            out.append("ham_enron_flagged")
        if "mail.links.ip_host" in ids:
            out.append("ham_enron_ip_host")
    for name in ("mail.sender.display_name_spoof", "mail.links.text_href_mismatch"):
        if name in ids and label == "ham":
            out.append(f"ham_has:{name.split('.')[-1]}")
        elif name in ids:
            out.append(f"{label}_has:{name.split('.')[-1]}")
    return out


def run_probe(layout: Layout, baseline: Layout) -> dict[str, Any]:
    """Tag every dev message of the baseline run; write aggregate counts only."""
    rows = {r["id"]: r for r in read_features(baseline, "dev") if r["source"] != "synthetic"}
    cohort_of = {i: cohorts_of(r) for i, r in rows.items()}
    sizes: Counter[str] = Counter()
    tag_counts: dict[str, Counter[str]] = defaultdict(Counter)
    finding_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for shard in range(baseline.shards):
        for item in read_jsonl(baseline.raw_shard(shard)):
            names = cohort_of.get(item["id"])
            if not names:
                continue
            tags = message_tags(base64.b64decode(item["b64"]))
            ids = {f[0] for f in kept_findings(rows[item["id"]], CONTENT)}
            for name in names:
                sizes[name] += 1
                tag_counts[name].update(tags)
                finding_counts[name].update(ids)
    body = {
        "schema_version": 1,
        "generated_at": now(),
        "min_cell": MIN_CELL,
        "cohorts": {
            name: {
                "n": sizes[name],
                "tags": {t: c for t, c in sorted(tag_counts[name].items()) if c >= MIN_CELL},
                "finding_ids": {t: c for t, c in sorted(finding_counts[name].items()) if c >= MIN_CELL},
            }
            for name in sorted(sizes)
        },
    }
    write_json(layout.reports / REPORT, body)
    return body
