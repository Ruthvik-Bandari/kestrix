# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""AI-assisted label audit of the vulnerable-labelled functions (``docs/data/policy.md``, section 6).

1. ``audit-sample`` (Slurm): a seeded random sample, stratified by language and label rule, of the
   train and dev records of ``work/split-v2.jsonl``. Test and test-extension records are never
   sampled: they are locked test inputs, which an AI assistant session must not receive. Each
   packet (``audit/packets.jsonl``, 0600) holds the advisory text, the CWEs, the function before and
   after the fix and their diff, plus its SHA-256.
2. Outside the repository, two independent reviewers (``ai-a``, ``ai-b``) judge each packet:
   ``vulnerable`` / ``not_vulnerable`` / ``unclear`` for the before-function and the stated
   advisory, ``fixes`` / ``does_not_fix`` / ``unclear`` for the after-function, and a one-line
   reason. A third reviewer adjudicates every disagreement on the before-function verdict.
   ``audit-combine`` turns the review files into ``verdicts.csv`` (ids, verdicts and packet hashes;
   no reasons) and the private ``verdicts-private.jsonl`` (with reasons).
3. ``audit-import`` (Slurm) validates ``verdicts.csv`` against the packets and writes
   ``work/audit_verdicts.jsonl`` and the aggregate ``reports/audit.json``: per-stratum label accuracy
   with Wilson 95% intervals, raw agreement and Cohen's kappa between the two reviewers, and the
   strata whose accuracy is below ``MIN_ACCURACY`` (excluded in the filtered view of manifest v2).

The per-record verdicts are evaluation metadata. They are not training labels, and they never
select training records for shipped weights (plan, licensing principle 3).
"""

from __future__ import annotations

import csv
import difflib
import hashlib
import io
import json
import math
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SEED = "kestrixvul-audit-v1"
PER_STRATUM = 25
TARGET = 240
MIN_ACCURACY = 0.80
MIN_STRATUM_N = 5
VERDICTS = ("vulnerable", "not_vulnerable", "unclear")
PATCH = ("fixes", "does_not_fix", "unclear")
AUDITED_SPLITS = ("train", "dev")
CSV_FIELDS = ("id", "packet_sha256", "verdict_a", "verdict_b", "final", "final_by", "patch_final")


class AuditError(ValueError):
    pass


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def stratum(record: dict[str, Any]) -> str:
    return f"{record['language']}/{record['label_rule']}"


def rank(rid: str, seed: str = SEED) -> str:
    return hashlib.sha256(f"{seed}\x1f{rid}".encode()).hexdigest()


def allocate(population: dict[str, int], per_stratum: int = PER_STRATUM, target: int = TARGET) -> dict[str, int]:
    """``per_stratum`` from every stratum (all of a smaller one), then the rest up to ``target``
    in proportion to the records each stratum still has."""
    take = {s: min(per_stratum, n) for s, n in population.items()}
    left = {s: n - take[s] for s, n in population.items()}
    room, pool = target - sum(take.values()), sum(left.values())
    if room <= 0 or pool == 0:
        return take
    room = min(room, pool)
    share = {s: room * left[s] / pool for s in left}
    extra = {s: math.floor(share[s]) for s in left}
    for s in sorted(left, key=lambda k: (extra[k] - share[k], k))[: room - sum(extra.values())]:
        extra[s] += 1  # largest remainders first
    return {s: take[s] + extra[s] for s in take}


def draw(records: list[dict[str, Any]], seed: str = SEED) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The seeded stratified sample of train/dev records and the population per stratum."""
    eligible = [r for r in records if r["split"] in AUDITED_SPLITS]
    by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in eligible:
        by_stratum[stratum(r)].append(r)
    population = {s: len(v) for s, v in sorted(by_stratum.items())}
    quota = allocate(population)
    chosen: list[dict[str, Any]] = []
    for s, recs in sorted(by_stratum.items()):
        chosen += sorted(recs, key=lambda r: rank(r["id"], seed))[: quota[s]]
    return sorted(chosen, key=lambda r: rank(r["id"], seed)), population


def packet_sha256(packet: dict[str, Any]) -> str:
    body = {k: v for k, v in packet.items() if k != "packet_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def function_diff(before: str, after: str | None) -> str:
    lines = difflib.unified_diff(
        before.splitlines(), (after or "").splitlines(), "before", "after" if after else "/dev/null", lineterm=""
    )
    return "\n".join(lines)


def _advisory_texts(root: Path, ids: set[str]) -> dict[str, str]:
    """{advisory id: text} from the GHSA advisories, then the CVE tables of both dumps."""
    texts: dict[str, str] = {}
    for adv in read_jsonl(root / "work" / "ghsa_text.jsonl"):
        text = "\n\n".join(t for t in (adv["summary"], adv["details"]) if t)
        for key in (adv["id"], *adv["aliases"]):
            if key in ids and text:
                texts.setdefault(key, text)
    for source in ("cvefixes", "morefixes"):
        path = root / "work" / f"{source}.sqlite"
        if not path.exists():
            continue
        db = sqlite3.connect(path)
        for cve in sorted(i for i in ids if i.startswith("CVE-")):
            row = db.execute("SELECT description FROM cve WHERE cve_id = ? LIMIT 1", (cve,)).fetchone()
            if row and row[0]:
                texts[f"nvd:{cve}"] = str(row[0])
        db.close()
    return texts


def sample(root: Path) -> dict[str, Any]:
    records = read_jsonl(root / "work" / "split-v2.jsonl")
    chosen, population = draw(records)
    texts = _advisory_texts(root, {a for r in chosen for a in r["advisory_ids"]})
    packets = []
    for r in chosen:
        advisories = [{"id": a, "text": texts[a]} for a in r["advisory_ids"] if a in texts]
        advisories += [{"id": a, "text": texts[f"nvd:{a}"]} for a in r["cve_ids"] if f"nvd:{a}" in texts]
        packet = {
            "id": r["id"],
            "stratum": stratum(r),
            "source": r["source"],
            "language": r["language"],
            "label_rule": r["label_rule"],
            "repo": r["repo"],
            "path": r["path"],
            "function": r["function"],
            "cwes": r["cwes"],
            "advisories": advisories,
            "before": r["vulnerable"],
            "after": r["patched"],
            "diff": function_diff(r["vulnerable"], r["patched"]),
        }
        packet["packet_sha256"] = packet_sha256(packet)
        packets.append(packet)
    write_private(root / "audit" / "packets.jsonl", "".join(json.dumps(p, sort_keys=True) + "\n" for p in packets))
    sampled = Counter(stratum(r) for r in chosen)
    return {
        "schema_version": 1,
        "seed": SEED,
        "audited_splits": list(AUDITED_SPLITS),
        "population_by_stratum": population,
        "sample_by_stratum": dict(sorted(sampled.items())),
        "sample_by_source": dict(sorted(Counter(r["source"] for r in chosen).items())),
        "sample_size": len(chosen),
        "with_advisory_text": sum(1 for p in packets if p["advisories"]),
        "ids_sha256": hashlib.sha256("".join(sorted(p["id"] + "\n" for p in packets)).encode()).hexdigest(),
    }


# --- combining the reviews (outside the repository) -----------------------------------------


def _reviews(rows: list[dict[str, Any]], who: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("verdict") not in VERDICTS or row.get("patch", "unclear") not in PATCH:
            raise AuditError(f"{who}: invalid verdict for {row.get('id')!r}")
        if not isinstance(row.get("reason"), str) or "\n" in row["reason"] or not row["reason"].strip():
            raise AuditError(f"{who}: {row.get('id')!r} needs a one-line reason")
        if row["id"] in out:
            raise AuditError(f"{who}: {row['id']!r} reviewed twice")
        out[row["id"]] = row
    return out


def combine(
    packets: list[dict[str, Any]], a: list[dict[str, Any]], b: list[dict[str, Any]], adjudicated: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One verdict row per packet; refuses missing reviews or a missing adjudication."""
    ra, rb, rc = _reviews(a, "ai-a"), _reviews(b, "ai-b"), _reviews(adjudicated, "ai-c")
    rows = []
    for p in packets:
        pid = p["id"]
        if pid not in ra or pid not in rb:
            raise AuditError(f"{pid}: needs both reviews")
        va, vb = ra[pid], rb[pid]
        if va["verdict"] == vb["verdict"]:
            final, final_by, patch = va["verdict"], "ai-consensus", va.get("patch", "unclear")
            if va.get("patch") != vb.get("patch"):
                patch = "unclear"
            reason = va["reason"]
        else:
            if pid not in rc:
                raise AuditError(f"{pid}: the reviewers disagree and there is no adjudication")
            final, final_by = rc[pid]["verdict"], "ai-adjudicated"
            patch, reason = rc[pid].get("patch", "unclear"), rc[pid]["reason"]
        rows.append(
            {
                "id": pid,
                "packet_sha256": p["packet_sha256"],
                "verdict_a": va["verdict"],
                "verdict_b": vb["verdict"],
                "final": final,
                "final_by": final_by,
                "patch_final": patch,
                "reason_a": va["reason"],
                "reason_b": vb["reason"],
                "reason_final": reason,
            }
        )
    return rows


def write_combined(folder: Path) -> dict[str, int]:
    """``folder/reviews/{a,b,adj}-*.jsonl`` -> ``verdicts.csv`` and ``verdicts-private.jsonl`` (0600)."""
    packets = read_jsonl(folder / "packets.jsonl")
    reviews = {k: [r for p in sorted((folder / "reviews").glob(f"{k}-*.jsonl")) for r in read_jsonl(p)] for k in ("a", "b", "adj")}  # fmt: skip
    rows = combine(packets, reviews["a"], reviews["b"], reviews["adj"])
    write_private(folder / "verdicts-private.jsonl", "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    write_private(folder / "verdicts.csv", buf.getvalue())
    return dict(Counter(r["final_by"] for r in rows))


# --- statistics -----------------------------------------------------------------------------


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    n = len(pairs)
    if n == 0:
        return None
    observed = sum(1 for x, y in pairs if x == y) / n
    ca, cb = Counter(x for x, _ in pairs), Counter(y for _, y in pairs)
    expected = sum(ca[k] * cb[k] for k in VERDICTS) / (n * n)
    return None if expected == 1 else round((observed - expected) / (1 - expected), 4)


def _accuracy(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(r["final"] for r in rows)
    n, ok = len(rows), counts["vulnerable"]
    decided = ok + counts["not_vulnerable"]
    return {
        "n": n,
        "final": {v: counts.get(v, 0) for v in VERDICTS},
        "label_accuracy": round(ok / n, 4) if n else None,
        "label_accuracy_ci95": wilson(ok, n),
        "label_accuracy_excluding_unclear": round(ok / decided, 4) if decided else None,
        "patch": dict(sorted(Counter(r["patch_final"] for r in rows).items())),
    }


def aggregate(
    packets: list[dict[str, Any]], verdicts: list[dict[str, Any]], population: dict[str, int]
) -> dict[str, Any]:
    by_id = {p["id"]: p for p in packets}
    rows = [
        v
        | {
            "stratum": by_id[v["id"]]["stratum"],
            "source": by_id[v["id"]]["source"],
            "source_rule": f"source:{by_id[v['id']]['source']}/{by_id[v['id']]['stratum'].split('/')[-1]}",
        }
        for v in verdicts
    ]
    per_stratum = {s: _accuracy([r for r in rows if r["stratum"] == s]) for s in sorted({r["stratum"] for r in rows})}
    for s, block in per_stratum.items():
        block["population"] = population.get(s, 0)
    weights = {s: population.get(s, 0) for s in per_stratum}
    total = sum(weights.values())
    weighted = sum((per_stratum[s]["label_accuracy"] or 0) * w for s, w in weights.items()) / total if total else None
    pairs = [(r["verdict_a"], r["verdict_b"]) for r in rows]
    per_source_rule = {
        k: _accuracy([r for r in rows if r["source_rule"] == k]) for k in sorted({r["source_rule"] for r in rows})
    }
    dropped = sorted(
        s
        for s, b in (per_stratum | per_source_rule).items()
        if b["n"] >= MIN_STRATUM_N and b["label_accuracy"] is not None and b["label_accuracy"] < MIN_ACCURACY
    )
    return {
        "schema_version": 1,
        "procedure": "AI-assisted (docs/data/policy.md section 6): two independent AI reviewers (ai-a, ai-b), "
        "a third adjudicates disagreements; no human review (owner decision). Train and dev records only.",
        "label_accuracy_definition": "share of audited records whose final verdict is 'vulnerable' (unclear "
        "counts as not confirmed); Wilson 95% interval",
        "audited": len(rows),
        "final_by": dict(sorted(Counter(r["final_by"] for r in rows).items())),
        "agreement": {
            "raw": round(sum(1 for x, y in pairs if x == y) / len(pairs), 4) if pairs else None,
            "cohen_kappa": cohen_kappa(pairs),
            "matrix": {f"{x}|{y}": n for (x, y), n in sorted(Counter(pairs).items())},
        },
        "overall": _accuracy(rows),
        "overall_weighted_by_population": round(weighted, 4) if weighted is not None else None,
        "per_stratum": per_stratum,
        "per_source": {
            s: _accuracy([r for r in rows if r["source"] == s]) for s in sorted({r["source"] for r in rows})
        },
        "per_source_rule": per_source_rule,
        "filter": {
            "min_accuracy": MIN_ACCURACY,
            "min_stratum_n": MIN_STRATUM_N,
            "dropped_strata": dropped,
        },
    }


def import_verdicts(root: Path, table: Path) -> dict[str, Any]:
    packets = read_jsonl(root / "audit" / "packets.jsonl")
    by_id = {p["id"]: p for p in packets}
    rows = list(csv.DictReader(io.StringIO(table.read_text(encoding="utf-8"))))
    seen: set[str] = set()
    for n, row in enumerate(rows, start=2):
        pid = row.get("id", "")
        if pid not in by_id or pid in seen:
            raise AuditError(f"line {n}: unknown or repeated id")
        seen.add(pid)
        if row.get("packet_sha256") != by_id[pid]["packet_sha256"]:
            raise AuditError(f"line {n}: packet hash differs from audit/packets.jsonl")
        if {row.get("verdict_a"), row.get("verdict_b"), row.get("final")} - set(VERDICTS):
            raise AuditError(f"line {n}: invalid verdict")
        if row.get("patch_final") not in PATCH:
            raise AuditError(f"line {n}: invalid patch verdict")
        agreed = row["verdict_a"] == row["verdict_b"]
        if row.get("final_by") != ("ai-consensus" if agreed else "ai-adjudicated") or (
            agreed and row["final"] != row["verdict_a"]
        ):
            raise AuditError(f"line {n}: final verdict inconsistent with the two reviews")
    if seen != set(by_id):
        raise AuditError(f"{len(set(by_id) - seen)} sampled packets have no verdict")
    verdicts = [{k: row[k] for k in CSV_FIELDS} for row in rows]
    write_private(
        root / "work" / "audit_verdicts.jsonl", "".join(json.dumps(v, sort_keys=True) + "\n" for v in verdicts)
    )
    population = json.loads((root / "reports" / "audit-sample.json").read_text())["population_by_stratum"]
    return aggregate(packets, verdicts, population)
