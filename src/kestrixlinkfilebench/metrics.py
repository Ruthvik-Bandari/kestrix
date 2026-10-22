# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Detection metrics for the URL checker and the file checker, with grouped bootstrap intervals.

Rates and intervals come from ``kestrixmailbench.metrics`` (``Frame``, ``rate``, ``ratio_entry``): every
interval is a 95% percentile bootstrap that resamples whole split groups (registered domain for links,
Govdocs thread for files); a cohort with fewer than 8 groups gets a message-level binomial interval
(``ci95_message``) instead.

Links. The URL checker's ``level`` is none, low, medium or high. "Caught at a level" is the share of phishing
at or above it; a false alarm is a benign URL at or above it. Precision is flagged phishing over all flagged
URLs at the corpus's own class mix, so it is not a real-world precision.

Files. The file checker has findings with severities and no level. A finding is *security*, *privacy* or
*context*; the alarm of a file is the highest severity among its security findings (privacy findings such as
GPS tags are about the owner, not about danger; context findings such as ``executable_file`` describe the file).
False alarms are measured on Govdocs, which is presumed benign but can hold real malware, so they are upper bounds.
Recall is measured only on synthetic cases, reported per family and never pooled with Govdocs.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np

from kestrixmailbench.metrics import REPS, SEED, Frame, rate, ratio_entry

from .common import BENIGN, PHISHING, SYNTHETIC
from .sources import GOVDOCS, MAJESTIC, PHIUSIIL

TOP = 15
RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3}
LEVELS = (("low_or_higher", 1), ("medium_or_higher", 2), ("high", 3))
SECURITY, PRIVACY, CONTEXT = "security", "privacy", "context"
FILE_CATEGORY = {
    "bidi_control_in_name": SECURITY,
    "double_extension": SECURITY,
    "extension_mismatch": SECURITY,
    "possible_packing": SECURITY,
    "high_entropy_file": SECURITY,
    "high_entropy_region": SECURITY,
    "macro_office_file": SECURITY,
    "encrypted_archive": SECURITY,
    "embedded_executable": SECURITY,
    "active_content_svg": SECURITY,
    "runnable_script_file": SECURITY,
    "executable_file": CONTEXT,
    "empty_file": CONTEXT,
    "expected_high_entropy": CONTEXT,
    "gps_location": PRIVACY,
    "identifying_metadata": PRIVACY,
}


def category(finding_id: str) -> str:
    """A file finding id's category; an id not listed counts as security, the strict side for false alarms."""
    return FILE_CATEGORY.get(finding_id, SECURITY)


def link_rank(frame: Frame) -> np.ndarray:
    return np.array([RANK[r["level"]] for r in frame.rows], dtype=np.int64)


def file_alarm(frame: Frame, categories: tuple[str, ...] = (SECURITY,)) -> np.ndarray:
    """Highest severity (0 none, 1 low, 2 medium, 3 high) among the findings of ``categories``."""
    return np.array(
        [max((RANK[sev] for fid, sev in r["findings"] if category(fid) in categories), default=0) for r in frame.rows],
        dtype=np.int64,
    )


def _top(counter: Counter[str], n: int, top: int = TOP) -> list[dict[str, Any]]:
    return [{"id": i, "items": c, "share": round(c / n, 4)} for i, c in counter.most_common(top)] if n else []


def _counts(frame: Frame, mask: np.ndarray) -> np.ndarray:
    return np.bincount(frame.group[mask], minlength=len(frame.group_names)).astype(float)


def link_cohorts(frame: Frame) -> dict[str, np.ndarray]:
    phiusiil = frame.source == PHIUSIIL
    benign = frame.label == BENIGN
    return {
        "phishing": phiusiil & (frame.label == PHISHING),
        "benign_phiusiil": phiusiil & benign,
        "benign_majestic": (frame.source == MAJESTIC) & benign,
        "benign_all": benign & np.isin(frame.source, (PHIUSIIL, MAJESTIC)),
    }


def link_table(frame: Frame, rank: np.ndarray, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """Catch, false-alarm and precision at each level, with grouped bootstrap intervals."""
    co = link_cohorts(frame)
    out: dict[str, Any] = {
        "n": {name: int(mask.sum()) for name, mask in co.items()},
        "groups": {name: len({int(g) for g in frame.group[mask]}) for name, mask in co.items()},
        "levels": {},
    }
    for name, k in LEVELS:
        flagged = rank >= k
        tp = _counts(frame, co["phishing"] & flagged)
        entry: dict[str, Any] = {"phishing_caught": rate(frame, co["phishing"], flagged, reps, seed)}
        for benign in ("benign_phiusiil", "benign_majestic", "benign_all"):
            entry[f"false_alarm_{benign}"] = rate(frame, co[benign], flagged, reps, seed)
            fp = _counts(frame, co[benign] & flagged)
            entry[f"precision_vs_{benign}"] = ratio_entry(frame, tp, tp + fp, reps, seed)
        out["levels"][name] = entry
    out["level_share"] = {
        cohort: {
            name: rate(frame, co[cohort], rank == k, reps, seed)
            for name, k in (("none", 0), ("low", 1), ("medium", 2), ("high", 3))
        }
        for cohort in ("phishing", "benign_all")
    }
    return out


def tld_table(frame: Frame, rank: np.ndarray, reps: int = REPS, seed: int = SEED, top: int = 12) -> dict[str, Any]:
    """Catch and false-alarm rates for the most common TLDs among phishing and among benign URLs."""
    co = link_cohorts(frame)
    tlds = np.array([r["tld"] for r in frame.rows], dtype=object)
    common = [t for t, _ in Counter(tlds[co["phishing"]]).most_common(top)]
    common += [t for t, _ in Counter(tlds[co["benign_all"]]).most_common(top) if t not in common]
    out: dict[str, Any] = {}
    for tld in common:
        phish, benign = co["phishing"] & (tlds == tld), co["benign_all"] & (tlds == tld)
        out[str(tld)] = {
            "n_phishing": int(phish.sum()),
            "n_benign": int(benign.sum()),
            "phishing_caught_low_or_higher": rate(frame, phish, rank >= 1, reps, seed) if phish.any() else None,
            "phishing_caught_medium_or_higher": rate(frame, phish, rank >= 2, reps, seed) if phish.any() else None,
            "false_alarm_low_or_higher": rate(frame, benign, rank >= 1, reps, seed) if benign.any() else None,
            "false_alarm_medium_or_higher": rate(frame, benign, rank >= 2, reps, seed) if benign.any() else None,
        }
    return out


def shape_table(frame: Frame, rank: np.ndarray, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """Catch and false-alarm rates by URL shape (scheme and bare host versus path or query)."""
    co = link_cohorts(frame)
    https = np.array([r["https"] for r in frame.rows], dtype=bool)
    pathy = np.array([bool(r["path"] or r["query"]) for r in frame.rows], dtype=bool)
    out: dict[str, Any] = {}
    for cohort in ("phishing", "benign_phiusiil", "benign_majestic"):
        for scheme, s_mask in (("https", https), ("http", ~https)):
            for shape, p_mask in (("bare", ~pathy), ("path_or_query", pathy)):
                mask = co[cohort] & s_mask & p_mask
                if mask.any():
                    out[f"{cohort}/{scheme}/{shape}"] = {
                        "n": int(mask.sum()),
                        "low_or_higher": rate(frame, mask, rank >= 1, reps, seed),
                        "medium_or_higher": rate(frame, mask, rank >= 2, reps, seed),
                    }
    return out


def link_causes(frame: Frame, rank: np.ndarray, top: int = TOP) -> dict[str, Any]:
    """Why the checker fails: finding ids among missed phishing and among benign false alarms."""
    co = link_cohorts(frame)
    out: dict[str, Any] = {"missed": {}, "false_alarms": {}}
    for label, k in (("below_medium", 2), ("none", 1)):
        idx = np.flatnonzero(co["phishing"] & (rank < k))
        ids: Counter[str] = Counter()
        for i in idx:
            ids.update({f[0] for f in frame.rows[int(i)]["findings"]})
        total = int(co["phishing"].sum())
        out["missed"][label] = {
            "cohort_size": total,
            "missed": len(idx),
            "miss_rate": round(len(idx) / total, 4) if total else None,
            "with_no_finding": sum(1 for i in idx if not frame.rows[int(i)]["findings"]),
            "ids_among_missed": _top(ids, len(idx), top),
        }
    for cohort in ("benign_phiusiil", "benign_majestic"):
        out["false_alarms"][cohort] = {}
        for label, k in (("low_or_higher", 1), ("medium_or_higher", 2)):
            idx = np.flatnonzero(co[cohort] & (rank >= k))
            ids = Counter()
            for i in idx:
                ids.update({f[0] for f in frame.rows[int(i)]["findings"] if RANK[f[1]] >= (1 if k == 1 else 2)})
            total = int(co[cohort].sum())
            out["false_alarms"][cohort][label] = {
                "cohort_size": total,
                "flagged": len(idx),
                "false_alarm_rate": round(len(idx) / total, 4) if total else None,
                "ids_among_flagged": _top(ids, len(idx), top),
            }
    return out


def finding_rates(frame: Frame, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """Share of phishing and of benign URLs that fire each finding id (any severity)."""
    co = link_cohorts(frame)
    ids = sorted({f[0] for r in frame.rows for f in r["findings"]})
    has = {fid: np.array([any(f[0] == fid for f in r["findings"]) for r in frame.rows], dtype=bool) for fid in ids}
    return {
        fid: {
            "phishing": rate(frame, co["phishing"], event, reps, seed),
            "benign_phiusiil": rate(frame, co["benign_phiusiil"], event, reps, seed),
            "benign_majestic": rate(frame, co["benign_majestic"], event, reps, seed),
        }
        for fid, event in has.items()
    }


def link_report(frame: Frame, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    rank = link_rank(frame)
    return {
        "metrics": link_table(frame, rank, reps, seed),
        "by_tld": tld_table(frame, rank, reps, seed),
        "by_shape": shape_table(frame, rank, reps, seed),
        "causes": link_causes(frame, rank),
        "finding_rates": finding_rates(frame, reps, seed),
    }


# --- files -------------------------------------------------------------------------------------------------


def file_cohorts(frame: Frame) -> dict[str, np.ndarray]:
    return {
        "govdocs": frame.source == GOVDOCS,
        "synthetic": frame.source == SYNTHETIC,
    }


def _alarm_rates(frame: Frame, mask: np.ndarray, alarm: np.ndarray, reps: int, seed: int) -> dict[str, Any]:
    return {name: rate(frame, mask, alarm >= k, reps, seed) for name, k in LEVELS}


def file_table(frame: Frame, reps: int = REPS, seed: int = SEED, min_n: int = 30) -> dict[str, Any]:
    """False-alarm rates on Govdocs overall, per detected type, per extension and per finding id."""
    gov = file_cohorts(frame)["govdocs"]
    security = file_alarm(frame, (SECURITY,))
    anything = file_alarm(frame, (SECURITY, PRIVACY))
    types = np.array([r["type"] for r in frame.rows], dtype=object)
    exts = np.array([r["ext"] for r in frame.rows], dtype=object)
    out: dict[str, Any] = {
        "n": int(gov.sum()),
        "groups": len({int(g) for g in frame.group[gov]}),
        "false_alarm_security": _alarm_rates(frame, gov, security, reps, seed),
        "false_alarm_security_or_privacy": _alarm_rates(frame, gov, anything, reps, seed),
        "by_type": {},
        "by_extension": {},
        "by_finding_id": {},
    }
    for key, values, label in (("by_type", types, "type"), ("by_extension", exts, "ext")):
        counts = Counter(values[gov])
        for value, n in counts.most_common():
            if n < (min_n if label == "type" else 100):
                continue
            mask = gov & (values == value)
            out[key][str(value)] = {"n": n, **_alarm_rates(frame, mask, security, reps, seed)}
    ids = sorted({f[0] for r in frame.rows for f in r["findings"]})
    for fid in ids:
        event = np.array([any(f[0] == fid for f in r["findings"]) for r in frame.rows], dtype=bool)
        if (gov & event).any():
            out["by_finding_id"][fid] = {"category": category(fid), "govdocs": rate(frame, gov, event, reps, seed)}
    return out


def file_causes(frame: Frame, top: int = 25) -> dict[str, Any]:
    """Which finding ids, detected types and extensions the Govdocs false alarms come from."""
    gov = file_cohorts(frame)["govdocs"]
    security = file_alarm(frame, (SECURITY,))
    out: dict[str, Any] = {}
    for label, k in (("medium_or_higher", 2), ("low_only", 1)):
        idx = np.flatnonzero(gov & (security >= k) & (security < (4 if k == 2 else 2)))
        ids: Counter[str] = Counter()
        cells: Counter[str] = Counter()
        for i in idx:
            row = frame.rows[int(i)]
            fired = {f[0] for f in row["findings"] if category(f[0]) == SECURITY and RANK[f[1]] >= k}
            ids.update(fired)
            cells.update(f"{fid} | {row['type']} | .{row['ext']}" for fid in fired)
        total = int(gov.sum())
        out[label] = {
            "flagged": len(idx),
            "false_alarm_rate": round(len(idx) / total, 4) if total else None,
            "ids": _top(ids, len(idx), top),
            "id_type_extension": _top(cells, len(idx), top),
        }
    return out


def synthetic_table(frame: Frame) -> dict[str, Any]:
    """Per synthetic family: caught at each level, expected finding id hits, ids fired. Never pooled with Govdocs."""
    syn = file_cohorts(frame)["synthetic"]
    security = file_alarm(frame, (SECURITY,))
    out: dict[str, Any] = {"families": {}}
    caught_all: list[float] = []
    for family in sorted({str(s) for s in frame.subset[syn]}):
        idx = np.flatnonzero(syn & (frame.subset == family))
        label = str(frame.label[idx[0]])
        fired: Counter[str] = Counter()
        for i in idx:
            fired.update({f[0] for f in frame.rows[int(i)]["findings"] if category(f[0]) == SECURITY})
        out["families"][family] = {
            "label": label,
            "n": len(idx),
            "alarm_low_or_higher": int((security[idx] >= 1).sum()),
            "alarm_medium_or_higher": int((security[idx] >= 2).sum()),
            "alarm_high": int((security[idx] >= 3).sum()),
            "security_ids_fired": dict(sorted(fired.items())),
        }
        if label != BENIGN:
            caught_all.append(float((security[idx] >= 2).mean()))
    families = out["families"]
    malicious = [f for f in families.values() if f["label"] != BENIGN]
    controls = [f for f in families.values() if f["label"] == BENIGN]
    out["summary"] = {
        "malicious_families": len(malicious),
        "malicious_families_fully_caught_medium_or_higher": sum(
            1 for f in malicious if f["alarm_medium_or_higher"] == f["n"]
        ),
        "malicious_files": sum(f["n"] for f in malicious),
        "malicious_caught_medium_or_higher": sum(f["alarm_medium_or_higher"] for f in malicious),
        "benign_control_files": sum(f["n"] for f in controls),
        "benign_control_alarm_medium_or_higher": sum(f["alarm_medium_or_higher"] for f in controls),
        "benign_control_alarm_low_or_higher": sum(f["alarm_low_or_higher"] for f in controls),
    }
    return out


def file_report(frame: Frame, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    exif = Counter(r["exif"] for r in frame.rows if r["source"] == GOVDOCS)
    return {
        "metrics": file_table(frame, reps, seed),
        "causes": file_causes(frame),
        "synthetic": synthetic_table(frame),
        "exif_status_govdocs": dict(sorted(exif.items())),
    }
