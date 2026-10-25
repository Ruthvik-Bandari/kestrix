# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev-only diagnostics of false-alarm causes, and proposed rule changes measured by monkeypatch.

Nothing here edits ``kestrix.mail``: a variant wraps analyzer functions of ``kestrix.mail.analyze`` for the duration
of one call. Diagnostics reduce every finding's evidence to a coarse *shape* (domains of well-known services kept,
every other host, address and word replaced by a placeholder) and suppress shapes seen fewer than five times.
"""

from __future__ import annotations

import importlib
import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from kestrix.mail.analyzers import org_domain
from kestrix.mail.models import Finding
from kestrix.mail.parse import Link, ParsedMessage

from .common import Layout, now, read_jsonl, write_json
from .modern_run import SYNTHETIC_MODERN as SYNTHETIC

MIN_SHAPE = 5
analyze_module: Any = importlib.import_module(
    "kestrix.mail.analyze"
)  # the module (the package re-exports the function)
# Organizational domains of public services and the projects behind the archives; every other domain is "<d>".
PUBLIC = frozenset(
    [
        "apache.org",
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "gnu.org",
        "gmail.com",
        "googlegroups.com",
        "google.com",
        "outlook.com",
        "microsoft.com",
        "live.com",
        "hotmail.com",
        "yahoo.com",
        "python.org",
        "kernel.org",
        "mozilla.org",
        "redhat.com",
        "ibm.com",
        "amazon.com",
        "amazonaws.com",
        "atlassian.net",
        "atlassian.com",
        "slack.com",
        "youtube.com",
        "wikipedia.org",
        "stackoverflow.com",
        "sourceforge.net",
        "debian.org",
        "ubuntu.com",
        "openssl.org",
        "w3.org",
        "ietf.org",
        "eclipse.org",
        "bitbucket.org",
        "medium.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "facebook.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "qq.com",
        "163.com",
        "126.com",
        "sina.com",
    ]
)
STRUCTURE = frozenset(
    [
        "from",
        "domain",
        "reply-to",
        "list",
        "domains",
        "return-path",
        "return",
        "path",
        "authserv-id",
        "dmarc=fail",
        "spf=fail",
        "text",
        "shows",
        "link",
        "goes",
        "to",
        "real",
        "host",
        "label",
        "displayed",
        "as",
        "redirects",
        "x-mailer",
        "display",
        "name",
        "names",
        "actual",
        "dkim",
        "header.d",
        "dkim=fail",
        "dmarc=none",
        "spf=softfail",
        "dmarc=pass",
        "spf=pass",
        "dkim=pass",
        "spf=none",
    ]
)
_URLISH = re.compile(r"(?:[a-z][a-z0-9+.-]*://)?([^\s/?#@:]+)")


def _host_class(host: str) -> str:
    host = host.strip("[]()<>\"',;.").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        kind = "loopback" if ip.is_loopback else "private" if ip.is_private else "public"
        return f"<ip-{kind}>"
    if "." in host and not host.startswith("."):
        return org_domain(host) if org_domain(host) in PUBLIC else "<d>"
    return "<w>"


def shape(evidence: str) -> str:
    """Evidence reduced to structure: placeholders for hosts, addresses, paths and words (see module docstring)."""
    out: list[str] = []
    for token in evidence[:300].split():
        bare = token.strip(",;()")
        if bare.lower() in STRUCTURE or bare.lower().rstrip(":") in STRUCTURE:
            out.append(bare.lower())
        elif "@" in bare:
            out.append("<a>")
        elif bare.replace(".", "").replace(":", "").isdigit() or bare.startswith("["):
            out.append(_host_class(bare))
        elif "." in bare or "/" in bare:
            match = _URLISH.match(bare)
            cls = _host_class(match.group(1)) if match else "<w>"
            out.append(cls + ("/<p>" if "/" in bare.split("//", 1)[-1] else ""))
        else:
            out.append("<w>")
    return " ".join(out[:14])


EVIDENCE_ANALYZERS = ("auth", "sender", "links", "lookalike")


def finding_shapes(findings: list[Finding]) -> list[tuple[str, str, str]]:
    """(id, severity, shape) for findings whose evidence is structural (never intent or attachment text)."""
    return [
        (f.id, f.severity, shape(f.evidence) if f.evidence and f.analyzer in EVIDENCE_ANALYZERS else "")
        for f in findings
    ]


REWRITER = re.compile(
    r"safelinks|urldefense|proofpoint|mimecast|linkprotect|secure-web|protection\.outlook|barracuda|safe\.|"
    r"nam\d\d\.|eur\d\d\.|can\d\d\.|aus\d\d\.|gbr\d\d\.|ind\d\d\."
)


def text_href_classes(raw: bytes) -> list[str]:
    """Coarse classes of every HTML link whose visible web address differs from the destination (no text kept)."""
    from urllib.parse import parse_qsl, urlsplit

    from kestrix.mail.analyzers import _shown_host, aligned
    from kestrix.mail.parse import normalize_domain, parse_message

    msg = parse_message(raw)
    from_domain = msg.from_.domain if msg.from_ else None
    out: list[str] = []
    for link in msg.links:
        shown = _shown_host(link)
        if shown is None:
            continue
        try:
            parts = urlsplit(link.href.strip())
            host = normalize_domain(parts.hostname or "")[0]
        except ValueError:
            continue
        if not host or aligned(shown, host) or (from_domain and aligned(shown, from_domain)):
            continue
        wrapped = ""
        for _, value in parse_qsl(parts.query)[:50]:
            if value.lower().startswith(("http://", "https://")):
                try:
                    wrapped = normalize_domain(urlsplit(value).hostname or "")[0]
                except ValueError:
                    wrapped = ""
                break
        cls = ["rewriter-host" if REWRITER.search(host) else "other-host"]
        if wrapped:
            cls.append("wrapped-target-matches-text" if aligned(wrapped, shown) else "wrapped-target-differs")
        else:
            cls.append("no-wrapped-target")
        cls.append("same-label" if org_domain(shown).split(".")[0] == org_domain(host).split(".")[0] else "diff-label")
        cls.append("text-public" if org_domain(shown) in PUBLIC else "text-other")
        cls.append("href-public" if org_domain(host) in PUBLIC else "href-other")
        cls.append("from-" + (_host_class(from_domain) if from_domain else "none").strip("<>"))
        out.append(" ".join(cls))
    return out


def run_diag(layout: Layout) -> int:
    """Re-analyze the flagged dev messages and count (source, id, shape); shapes under five are pooled."""
    import base64

    from kestrix.mail import analyze

    meta = {m["id"]: m for m in read_jsonl(layout.meta)}
    counts: Counter[tuple[str, str, str, str]] = Counter()
    flagged_n: Counter[str] = Counter()
    by_list: Counter[tuple[str, str]] = Counter()
    mismatch: Counter[str] = Counter()
    mismatch_messages = 0
    for shard in range(layout.shards):
        for item in read_jsonl(layout.raw_shard(shard)):
            info = meta[item["id"]]
            if info["split"] != "dev":
                continue
            report = analyze(base64.b64decode(item["b64"]))
            if report.verdict not in ("suspicious", "malicious"):
                continue
            flagged_n[info["source"]] += 1
            for fid in {f.id for f in report.findings if f.severity in ("medium", "high")}:
                by_list[(f"{info['source']}|{info['subset']}", fid)] += 1
            if any(f.id == "mail.links.text_href_mismatch" for f in report.findings):
                mismatch_messages += 1
                mismatch.update(set(text_href_classes(base64.b64decode(item["b64"]))))
            for fid, sev, sh in finding_shapes(report.findings):
                if sev != "info":
                    counts[(info["source"], fid, sev, sh)] += 1
    kept: dict[str, list[dict[str, Any]]] = {}
    pooled: Counter[tuple[str, str]] = Counter()
    for (source, fid, sev, sh), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        if n >= MIN_SHAPE:
            kept.setdefault(source, []).append({"id": fid, "severity": sev, "shape": sh, "messages": n})
        else:
            pooled[(source, fid)] += n
    write_json(
        layout.reports / "modern-diag.json",
        {
            "schema_version": 1,
            "generated_at": now(),
            "split": "dev",
            "flagged_messages": dict(flagged_n),
            "min_shape_count": MIN_SHAPE,
            "shapes": kept,
            "suppressed": {f"{s}|{i}": n for (s, i), n in sorted(pooled.items())},
            "flagged_medium_high_ids_by_list": {
                f"{lst}|{fid}": n for (lst, fid), n in sorted(by_list.items(), key=lambda kv: -kv[1]) if n >= MIN_SHAPE
            },
            "text_href_mismatch_messages": mismatch_messages,
            "text_href_mismatch_link_classes": {k: n for k, n in mismatch.most_common(40) if n >= MIN_SHAPE},
        },
    )
    return 0


FREEMAIL = frozenset(
    {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com"}
    | {"protonmail.com", "proton.me", "qq.com", "163.com", "126.com", "mykolab.com"}
)

LinkPre = Callable[[ParsedMessage], ParsedMessage]
FindingsPost = Callable[[ParsedMessage, list[Finding]], list[Finding]]


def _links_changed(msg: ParsedMessage, change: Callable[[Link], Link]) -> ParsedMessage:
    return replace(msg, links=tuple(change(link) for link in msg.links))


def pre_unwrap_rewriters(msg: ParsedMessage) -> ParsedMessage:
    """P1: a link through a URL-rewriting gateway is judged by the address it wraps; if none can be read, its
    visible text is not compared (the destination is unknown, so a mismatch cannot be claimed)."""
    from urllib.parse import parse_qsl, urlsplit

    from kestrix.mail.parse import normalize_domain

    def change(link: Link) -> Link:
        try:
            parts = urlsplit(link.href.strip())
            host = normalize_domain(parts.hostname or "")[0]
        except ValueError:
            return link
        if not host or not REWRITER.search(host):
            return link
        for _, value in parse_qsl(parts.query)[:50]:
            if value.lower().startswith(("http://", "https://")):
                return replace(link, href=value)
        return replace(link, text="")

    return _links_changed(msg, change)


def pre_tracker_text(msg: ParsedMessage) -> ParsedMessage:
    """P4: bare-address link text on a click-tracking destination is not compared with the destination."""
    from urllib.parse import urlsplit

    from kestrix.mail.analyzers import _looks_like_tracking
    from kestrix.mail.parse import normalize_domain

    def change(link: Link) -> Link:
        try:
            parts = urlsplit(link.href.strip())
            host = normalize_domain(parts.hostname or "")[0]
        except ValueError:
            return link
        return replace(link, text="") if host and _looks_like_tracking(host, parts.path) else link

    return _links_changed(msg, change)


def _is_private_ip_finding(finding: Finding) -> bool:
    if finding.id != "mail.links.ip_host" or not finding.evidence:
        return False
    try:
        return not ipaddress.ip_address(finding.evidence.removeprefix("host ").strip("[]")).is_global
    except ValueError:
        return False


def post_private_ip(msg: ParsedMessage, findings: list[Finding]) -> list[Finding]:
    """P3: a link to a private, loopback or link-local address is info: it cannot be reached from outside."""
    return [f.model_copy(update={"severity": "info"}) if _is_private_ip_finding(f) else f for f in findings]


def _freemail_reply(finding: Finding) -> bool:
    if finding.id != "mail.sender.reply_to_mismatch" or not finding.evidence:
        return False
    domains = {d.strip() for d in finding.evidence.split("Reply-To domain", 1)[-1].split(",")}
    return bool(domains) and all(org_domain(d) in FREEMAIL for d in domains)


def post_list_freemail_reply(msg: ParsedMessage, findings: list[Finding]) -> list[Finding]:
    """P6: on list mail, a Reply-To at a free-mail provider is a participant's own setting: low, not medium."""
    from kestrix.mail.analyzers import list_domains

    if not list_domains(msg):
        return findings
    return [f.model_copy(update={"severity": "low"}) if _freemail_reply(f) else f for f in findings]


def topmost_dmarc_passed(msg: ParsedMessage, trusted_authserv_ids: frozenset[str] = frozenset()) -> bool:
    """The rule before the 2026-10-25 fix: without a trusted authserv-id, the topmost header's ``dmarc=pass`` was
    believed and lowered ``mail.intent.credential_request`` to low. Kept to measure what the fix changed."""
    from kestrix.mail.analyzers import trusted_results

    chosen = trusted_results(msg, trusted_authserv_ids)
    return chosen is not None and any(r.method == "dmarc" and r.result == "pass" for r in chosen.results)


# name -> names in ``kestrix.mail.analyze`` replaced for that variant (besides the link and sender wrappers)
PATCHES: dict[str, dict[str, Callable[..., Any]]] = {"before_auth_fix": {"dmarc_passed": topmost_dmarc_passed}}

# name -> (link pre-processors, link post-processors, sender post-processors)
VARIANTS: dict[str, tuple[tuple[LinkPre, ...], tuple[FindingsPost, ...], tuple[FindingsPost, ...]]] = {
    "base": ((), (), ()),
    "before_auth_fix": ((), (), ()),
    "p1_unwrap_rewriters": ((pre_unwrap_rewriters,), (), ()),
    "p3_private_ip": ((), (post_private_ip,), ()),
    "p4_tracker_text": ((pre_tracker_text,), (), ()),
    "p6_list_freemail_reply": ((), (), (post_list_freemail_reply,)),
    "p1_p3_p6": ((pre_unwrap_rewriters,), (post_private_ip,), (post_list_freemail_reply,)),
    "p1_p3_p4_p6": ((pre_unwrap_rewriters, pre_tracker_text), (post_private_ip,), (post_list_freemail_reply,)),
}


def analyze_variant(raw: bytes, name: str) -> str:
    """Verdict of ``raw`` under variant ``name`` (current ``kestrix.mail`` code plus the named bench-side patches)."""
    pres, link_posts, sender_posts = VARIANTS[name]
    orig_links, orig_sender = analyze_module.analyze_links, analyze_module.analyze_sender

    def links(msg: ParsedMessage) -> list[Finding]:
        changed = msg
        for pre in pres:
            changed = pre(changed)
        found: list[Finding] = orig_links(changed)
        for post in link_posts:
            found = post(msg, found)
        return found

    def sender(msg: ParsedMessage, protected: frozenset[str] = frozenset()) -> list[Finding]:
        found: list[Finding] = orig_sender(msg, protected)
        for post in sender_posts:
            found = post(msg, found)
        return found

    with patched(analyze_links=links, analyze_sender=sender, **PATCHES.get(name, {})):
        return str(analyze_module.analyze(raw).verdict)


def _old_dev_rows(layout: Layout, shard: int) -> Iterator[tuple[dict[str, Any], bytes]]:
    """Dev messages of the earlier 1999-2005 / phishing benchmark in this shard (its locked test is never read)."""
    import base64

    from .build import read_meta
    from .split import read_split

    base = Layout(Path(str(layout.root).replace("mailmodern", "mailbench")), layout.shards)
    meta = {m["id"]: m for m in read_meta(base)}
    split_of = read_split(base)
    for item in read_jsonl(base.raw_shard(shard)):
        info = meta[item["id"]]
        if split_of[item["id"]] == "dev" and info["source"] != "synthetic":
            yield info, base64.b64decode(item["b64"])


def variant_names(spec: str | None) -> tuple[str, ...]:
    """``base`` plus the comma-separated variants in ``spec``, or every variant when ``spec`` is empty."""
    if not spec:
        return tuple(VARIANTS)
    names = ("base", *(name for name in spec.split(",") if name and name != "base"))
    unknown = [name for name in names if name not in VARIANTS]
    if unknown:
        from .common import MailBenchError

        raise MailBenchError(f"unknown variants: {', '.join(unknown)}")
    return names


def run_variants(
    layout: Layout, shard: int | None, with_old: bool = True, names: tuple[str, ...] = tuple(VARIANTS), tag: str = ""
) -> int:
    """Verdicts of the variants for the modern dev and synthetic messages (and the old dev corpora) of a shard,
    written to ``modern-variants{tag}-shard-NN.jsonl``."""
    import base64

    meta = {m["id"]: m for m in read_jsonl(layout.meta)}
    rows: list[dict[str, Any]] = []

    def record(info: dict[str, Any], data: bytes, origin: str) -> None:
        keep = {k: info[k] for k in ("id", "source", "subset", "label", "year", "group")}
        rows.append({**keep, "origin": origin, "v": {name: analyze_variant(data, name) for name in names}})

    for item in read_jsonl(layout.raw_shard(shard if shard is not None else 0)):
        info = meta[item["id"]]
        if info["split"] in ("dev", "synthetic"):
            record(info, base64.b64decode(item["b64"]), "modern")
    if with_old:
        for info, data in _old_dev_rows(layout, shard if shard is not None else 0):
            record(info, data, "old")
    from .common import write_jsonl

    write_jsonl(layout.features / f"modern-variants{tag}-shard-{shard:02d}.jsonl", rows)
    return 0


@contextmanager
def patched(**replacements: Callable[..., Any]) -> Iterator[None]:
    """Replace names in ``kestrix.mail.analyze`` for the duration of the block."""
    original = {name: getattr(analyze_module, name) for name in replacements}
    for name, fn in replacements.items():
        setattr(analyze_module, name, fn)
    try:
        yield
    finally:
        for name, fn in original.items():
            setattr(analyze_module, name, fn)


def variants_report(layout: Layout, reps: int, tag: str = "") -> dict[str, Any]:
    """Per variant: flagged and malicious rates on the modern dev lists and on the old dev corpora, with CIs, and
    how many verdicts differ from ``base`` (counts per cohort and per verdict transition)."""
    import numpy as np

    from .metrics import Frame, rate

    rows: list[dict[str, Any]] = []
    for shard in range(layout.shards):
        rows.extend(read_jsonl(layout.features / f"modern-variants{tag}-shard-{shard:02d}.jsonl"))
    rows.sort(key=lambda r: (r["origin"], r["id"]))
    frame = Frame(rows)
    src, lab = frame.source, frame.label
    cohorts = {
        "modern_ham_all": np.isin(src, ["asf", "gnu"]),
        "modern_asf": src == "asf",
        "modern_gnu": src == "gnu",
        "asf_dev_spark": (src == "asf") & (frame.subset == "dev-spark"),
        "asf_user_spark": (src == "asf") & (frame.subset == "user-spark"),
        "old_phishing": (src == "nazario") & (lab == "phishing"),
        "old_spam": (src == "spamassassin") & (lab == "spam"),
        "old_spamassassin_ham": (src == "spamassassin") & (lab == "ham"),
        "old_enron_ham": src == "enron",
    }
    out: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now(),
        "split": "dev",
        "n": {name: int(mask.sum()) for name, mask in cohorts.items()},
        "variants": {},
    }
    synth = src == SYNTHETIC
    cohorts_changed = cohorts | {"synthetic_modern": synth}
    base = np.array([r["v"]["base"] for r in rows], dtype=object)
    for name in rows[0]["v"] if rows else ():
        verdict = np.array([r["v"][name] for r in rows], dtype=object)
        flagged = np.asarray((verdict == "suspicious") | (verdict == "malicious"), dtype=bool)
        malicious = np.asarray(verdict == "malicious", dtype=bool)
        changed = np.asarray(verdict != base, dtype=bool)
        out["variants"][name] = {
            cohort: {"flagged": rate(frame, mask, flagged, reps, 0), "malicious": rate(frame, mask, malicious, reps, 0)}
            for cohort, mask in cohorts.items()
        } | {
            "synthetic_modern_flagged": int((flagged & synth).sum()),
            "changed_vs_base": {
                cohort: {
                    "messages": int((changed & mask).sum()),
                    "transitions_base_to_variant": dict(
                        sorted(
                            Counter(
                                f"{b}->{v}" for b, v in zip(base[changed & mask], verdict[changed & mask], strict=True)
                            ).items()
                        )
                    ),
                }
                for cohort, mask in cohorts_changed.items()
            },
        }
    return out
