# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Aggregate reports for modern normal mail: dev, synthetic and the one-time held-out run. No ids, text or addresses."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from typing import Any

import numpy as np

from .common import Layout, MailBenchError, now, write_json
from .metrics import ALL, CONTENT, Frame, Scoring, baseline_scoring, rate
from .modern_run import SYNTHETIC_MODERN, analyze_shard, read_split_features

TOP = 20
AUTH_IDS = ("mail.auth.dmarc_fail", "mail.auth.no_dmarc_with_failure", "mail.auth.spf_fail", "mail.auth.spf_softfail")


def _entry(frame: Frame, mask: np.ndarray, scoring: Scoring, reps: int, seed: int) -> dict[str, Any]:
    return {
        "flagged": rate(frame, mask, scoring.flagged, reps, seed),
        "malicious": rate(frame, mask, scoring.malicious, reps, seed),
    }


def _share(counter: Counter[str], n: int, top: int = TOP) -> list[dict[str, Any]]:
    return [{"id": k, "messages": c, "share": round(c / n, 4)} for k, c in counter.most_common(top)] if n else []


def verdict_report(frame: Frame, scoring: Scoring, reps: int, seed: int) -> dict[str, Any]:
    """Flagged and malicious rates overall, per source, list, year and automation flag, with group bootstrap CIs."""
    everything = np.ones(len(frame), dtype=bool)
    auto = np.array([bool(r["auto"]) for r in frame.rows], dtype=bool)
    out: dict[str, Any] = {
        "n": len(frame),
        "groups": len(frame.group_names),
        "all": _entry(frame, everything, scoring, reps, seed),
        "by_source": {s: _entry(frame, frame.source == s, scoring, reps, seed) for s in sorted(set(frame.source))},
        "by_list": {
            f"{s}|{lst}": _entry(frame, (frame.source == s) & (frame.subset == lst), scoring, reps, seed)
            for s, lst in sorted(set(zip(frame.source, frame.subset, strict=True)))
        },
        "by_year": {
            str(y): _entry(frame, frame.year == y, scoring, reps, seed) for y in sorted({int(v) for v in frame.year})
        },
        "by_source_year": {
            f"{s}|{y}": _entry(frame, (frame.source == s) & (frame.year == y), scoring, reps, seed)
            for s in sorted(set(frame.source))
            for y in sorted({int(v) for v in frame.year[frame.source == s]})
        },
        "automated_notification": {
            "marked_automated": _entry(frame, auto, scoring, reps, seed),
            "not_marked": _entry(frame, ~auto, scoring, reps, seed),
        },
        "verdict_counts": dict(sorted(Counter(scoring.verdict.tolist()).items())),
    }
    return out


def causes_report(rows: list[dict[str, Any]], scoring: Scoring) -> dict[str, Any]:
    """Finding ids in the whole sample and in the flagged messages, and the sets of medium/high ids that flag."""
    n = len(rows)
    every: Counter[str] = Counter()
    for r in rows:
        every.update({f[0] for f in r["findings"]})
    flagged_idx = np.flatnonzero(scoring.flagged)
    serious: Counter[str] = Counter()
    sets: Counter[str] = Counter()
    low_in_combo: Counter[str] = Counter()
    for i in flagged_idx:
        findings = rows[i]["findings"]
        ids = {f[0] for f in findings if f[1] in ("medium", "high")}
        serious.update(ids)
        sets["+".join(sorted(ids)) or "weak_combination_of_low_findings"] += 1
        if not ids:
            low_in_combo.update({f[0] for f in findings if f[1] == "low"})
    return {
        "finding_share_all_messages": _share(every, n, 40),
        "medium_or_high_ids_among_flagged": _share(serious, len(flagged_idx)),
        "flagging_id_sets": _share(sets, len(flagged_idx), 25),
        "low_ids_among_weak_combination_flags": _share(
            low_in_combo, sum(sets[k] for k in sets if k.startswith("weak"))
        ),
        "flagged": len(flagged_idx),
        "malicious_id_sets": _share(
            Counter(
                "+".join(sorted({f[0] for f in rows[i]["findings"] if f[1] == "high"}))
                for i in np.flatnonzero(scoring.malicious)
            ),
            int(scoring.malicious.sum()),
        ),
    }


def auth_report(rows: list[dict[str, Any]], scoring: Scoring) -> dict[str, Any]:
    """What the auth analyzer saw: header presence, method results, and the findings and flags they produced."""
    n = len(rows)
    with_ar = [r for r in rows if r["ar"]]
    methods: dict[str, Counter[str]] = {m: Counter() for m in ("dkim", "spf", "dmarc")}
    for r in with_ar:
        for m, counter in methods.items():
            counter["/".join(r["ar"][m]) or "absent"] += 1
    by_source: dict[str, Any] = {}
    for s in sorted({r["source"] for r in rows}):
        sub = [r for r in rows if r["source"] == s]
        by_source[s] = {
            "n": len(sub),
            "authentication_results_present": sum(1 for r in sub if r["ar"]),
            "more_than_one_authentication_results": sum(1 for r in sub if r["ar_count"] > 1),
            "arc_seal_present": sum(1 for r in sub if r["arc"]),
            "dkim_signature_present": sum(1 for r in sub if r["dkim_sigs"]),
            "received_spf_present": sum(1 for r in sub if r["received_spf"]),
        }
    finding_ids: Counter[str] = Counter()
    flagged_by_auth = 0
    for r, flagged in zip(rows, scoring.flagged, strict=True):
        ids = {f[0] for f in r["findings"] if f[0].startswith("mail.auth.")}
        finding_ids.update(ids)
        if flagged and any(f[0] in AUTH_IDS for f in r["findings"] if f[1] in ("medium", "high")):
            flagged_by_auth += 1
    return {
        "n": n,
        "by_source": by_source,
        "authserv_ids": dict(Counter(r["ar"]["authserv"] for r in with_ar).most_common(10)),
        "method_results": {m: dict(c.most_common(8)) for m, c in methods.items()},
        "auth_finding_messages": dict(finding_ids.most_common()),
        "flagged_with_an_auth_medium_or_high_finding": flagged_by_auth,
    }


def reply_to_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The round-1 mailing-list Reply-To exemption on modern lists."""
    foreign = [
        r
        for r in rows
        if any(f[0] in ("mail.sender.reply_to_mailing_list", "mail.sender.reply_to_mismatch") for f in r["findings"])
    ]
    out: dict[str, Any] = {
        "messages": len(rows),
        "with_reply_to_header": sum(1 for r in rows if r["reply_to"]),
        "with_list_id": sum(1 for r in rows if r["list_id"]),
        "foreign_reply_to": len(foreign),
        "by_source": {},
    }
    for s in sorted({r["source"] for r in rows}):
        sub = [r for r in foreign if r["source"] == s]
        ids = Counter(f[0] for r in sub for f in r["findings"] if f[0].startswith("mail.sender.reply_to"))
        out["by_source"][s] = {
            "foreign_reply_to": len(sub),
            "explained_by_list_headers": ids["mail.sender.reply_to_mailing_list"],
            "still_reply_to_mismatch": ids["mail.sender.reply_to_mismatch"],
            "with_list_id_among_still_mismatch": sum(
                1 for r in sub if r["list_id"] and any(f[0] == "mail.sender.reply_to_mismatch" for f in r["findings"])
            ),
        }
    return out


def full_report(rows: list[dict[str, Any]], split: str, reps: int, seed: int = 0) -> dict[str, Any]:
    frame = Frame(rows)
    all_scoring = baseline_scoring(frame, ALL)
    content_scoring = baseline_scoring(frame, CONTENT)
    return {
        "schema_version": 1,
        "split": split,
        "generated_at": now(),
        "bootstrap": {"resamples": reps, "seed": seed, "unit": "list and year"},
        "all_findings": verdict_report(frame, all_scoring, reps, seed),
        "content_only": {"all": _entry(frame, np.ones(len(frame), dtype=bool), content_scoring, reps, seed)},
        "causes": causes_report(rows, all_scoring),
        "auth": auth_report(rows, all_scoring),
        "reply_to": reply_to_report(rows),
    }


def synthetic_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for family in sorted({r["subset"] for r in rows}):
        sub = [r for r in rows if r["subset"] == family]
        ids = Counter(f[0] for r in sub for f in r["findings"])
        out[family] = {
            "n": len(sub),
            "flagged": sum(1 for r in sub if r["verdict"] in ("suspicious", "malicious")),
            "malicious": sum(1 for r in sub if r["verdict"] == "malicious"),
            "finding_ids": dict(sorted(ids.items())),
        }
    return {"source": SYNTHETIC_MODERN, "families": out}


def run_report(args: argparse.Namespace, layout: Layout) -> int:
    if args.command == "report":
        rows = read_split_features(layout, "dev")
        body = full_report(rows, "dev", args.bootstrap)
        body["synthetic"] = synthetic_report(read_split_features(layout, "synthetic"))
        write_json(layout.reports / "modern-dev.json", body)
        print(f"wrote {layout.reports / 'modern-dev.json'}")
        return 0
    if args.command == "heldout":
        return heldout(layout, args.bootstrap)
    if args.command == "diag":
        from .modern_proposals import run_diag

        return run_diag(layout)
    if args.command == "variants-report":
        from .modern_proposals import variants_report

        tag = variants_tag(args.tag)
        write_json(layout.reports / f"modern-variants{tag}.json", variants_report(layout, args.bootstrap, tag))
        return 0
    if args.command == "variants":
        from .modern_proposals import run_variants, variant_names

        return run_variants(layout, args.shard, names=variant_names(args.variants), tag=variants_tag(args.tag))
    raise MailBenchError(f"unknown command {args.command}")


def variants_tag(tag: str | None) -> str:
    """File-name suffix for a variants run: ``""`` or ``-<tag>`` (lower-case letters, digits and hyphens)."""
    if not tag:
        return ""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", tag):
        raise MailBenchError("--tag takes lower-case letters, digits and hyphens")
    return f"-{tag}"


def heldout(layout: Layout, reps: int) -> int:
    """Claim the lock (exclusive create), analyze the held-out lists once with the current rules, write the report."""
    from kestrixvul.evaluate import claim_locked, finish_claim

    claim = claim_locked(layout.root, {"name": "modern-heldout-current-rules", "rules": "unmodified kestrix.mail"})
    for shard in range(layout.shards):
        analyze_shard(layout, shard, ("heldout",))
    rows = read_split_features(layout, "heldout")
    path = layout.reports / "modern-heldout.json"
    write_json(path, full_report(rows, "heldout", reps))
    finish_claim(claim, path)
    print(f"wrote {path}")
    return 0
