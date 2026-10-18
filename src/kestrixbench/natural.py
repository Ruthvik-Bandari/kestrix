# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Natural maintenance faults mined from SigmaHQ's own history (plan section 11, provenance ``natural``).

Each commit that modified a Windows process_creation rule is a maintenance event. The version
before the commit is the *impaired* rule, and the version after it is the maintainers' *fix*.
Stage 1 (``mine``) walks the history up to the pinned commit and keeps pairs where both versions
fall within the supported subset and the detection logic changed. It then classifies each change
with an AST diff, not a text diff:

- ``condition``: the condition was edited;
- ``values_added`` / ``values_removed``: a predicate's value list was extended or narrowed;
- ``modifier``: a predicate's modifier or ``|all`` changed;
- ``field``: a selection now tests a different field;
- ``selection_added`` / ``selection_removed``: a selection was added or removed.

Each pair is also scored with an approximate AST edit count, and ``within_contract`` says whether
the fix fits the repair contract: at most 3 edits, no removed selection, and at most 8 values per
changed predicate.

Pure renamings of selections are skipped as refactors.

Stage 2 (``verify_all``) replays every pair against one global pool of verified positives: every
SigmaHQ regression event (a real attack recording) and every OTRF event a reviewer labeled
malicious. A pair is *verified* when the fix detects a pool event that the earlier version misses,
which is a real coverage fault and its real fix. False-positive fixes cannot be verified without
reviewed benign events, so they are counted and never guessed at. The split builder adds verified
rules as roots, grouped with any rule that shares their events, so no event leaks across splits.

Stage 3 (``build``) writes one case per verified pair whose root landed in the train, development
or test split. Reserve roots never enter the benchmark.

The rule texts come from a public repository, so the mining output is shareable. Case folders hold
event values and stay private on the cluster.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.detect.candidate import condition_edits
from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Event
from kestrix.detect.rule import And, Cond, Not, Or, Ref, Rule, parse_rule, render_condition

from .positives import otrf_events, sigma_events
from .qc import SIGMA_RULES
from .variants import (
    HEALTHY,
    Variant,
    _matched,
    background_negatives,
    fixtures,
    known_positives,
    to_ecs,
    write_case,
)

GIT_TIMEOUT_S = 600
MAX_RULE_BYTES = 100 * 1024
_SEP = "\x1f"


@dataclass(frozen=True)
class Change:
    commit: str
    date: str
    subject: str
    path: str
    rule_id: str
    kinds: tuple[str, ...]
    edits: int
    within_contract: bool
    before: str
    after: str


def _git(git_dir: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        # core.quotePath=false: non-ASCII rule paths come back verbatim instead of quoted.
        ["git", "-c", "core.quotePath=false", f"--git-dir={git_dir}", *args],  # noqa: S607 - git from PATH
        input=stdin,
        capture_output=True,
        timeout=GIT_TIMEOUT_S,
        check=True,
    ).stdout


def modifications(git_dir: Path, pinned: str) -> Iterator[tuple[str, str, str, str, str]]:
    """``(commit, date, subject, old_path, new_path)`` for every modified or renamed rule file."""
    out = _git(
        git_dir,
        "log",
        "--no-merges",
        f"--format=@@{_SEP}%H{_SEP}%cI{_SEP}%s",
        "--name-status",
        "-M",
        "--diff-filter=MR",
        pinned,
        "--",
        SIGMA_RULES,
    ).decode("utf-8", errors="replace")
    commit = date = subject = ""
    for line in out.splitlines():
        if line.startswith(f"@@{_SEP}"):
            _, commit, date, subject = line.split(_SEP, 3)
            continue
        parts = line.split("\t")
        if not parts[0] or not commit:
            continue
        old, new = (parts[1], parts[2]) if parts[0].startswith("R") and len(parts) == 3 else (parts[-1], parts[-1])
        if new.endswith(".yml") and new.startswith(SIGMA_RULES + "/"):
            yield commit, date, subject, old, new


def _blobs(git_dir: Path, specs: list[str]) -> list[bytes | None]:
    """Read many ``rev:path`` objects with one ``git cat-file --batch``; None when missing or too large."""
    raw = _git(git_dir, "cat-file", "--batch", stdin=("\n".join(specs) + "\n").encode())
    out: list[bytes | None] = []
    pos = 0
    for _ in specs:
        end = raw.index(b"\n", pos)
        header = raw[pos:end].split()
        pos = end + 1
        if len(header) < 3 or header[1] != b"blob":
            out.append(None)
            continue
        size = int(header[2])
        out.append(raw[pos : pos + size] if size <= MAX_RULE_BYTES else None)
        pos += size + 1
    return out


def _rename(cond: Cond, names: dict[str, str]) -> Cond:
    match cond:
        case Ref(name):
            return Ref(names.get(name, name))
        case Not(op):
            return Not(_rename(op, names))
        case And(ops):
            return And(tuple(_rename(o, names) for o in ops))
        case Or(ops):
            return Or(tuple(_rename(o, names) for o in ops))
    raise TypeError(cond)


def is_refactor(before: Rule, after: Rule) -> bool:
    """True when the versions differ only by selection names (a restyling, not a fault)."""
    if sorted(map(repr, before.selections.values())) != sorted(map(repr, after.selections.values())):
        return False
    by_body = {repr(sel): name for name, sel in after.selections.items()}
    names = {name: by_body.get(repr(sel), name) for name, sel in before.selections.items()}
    return _rename(before.condition, names) == after.condition


def classify(before: Rule, after: Rule) -> tuple[tuple[str, ...], int, bool]:
    """Change kinds, approximate AST edits, and whether the fix fits the repair contract."""
    kinds: set[str] = set()
    edits = 0
    added = after.selections.keys() - before.selections.keys()
    removed = before.selections.keys() - after.selections.keys()
    if added:
        kinds.add("selection_added")
        edits += sum(1 + len(after.selections[n].predicates) for n in added)
    if removed:
        kinds.add("selection_removed")
    if render_condition(before.condition) != render_condition(after.condition):
        kinds.add("condition")
        edits += 0 if (added or removed) else condition_edits(before.condition, after.condition)
    big_values = False
    reshaped = False
    for name in before.selections.keys() & after.selections.keys():
        b_sel, a_sel = before.selections[name], after.selections[name]
        if [[p.field for p in br] for br in b_sel.branches] != [[q.field for q in br] for br in a_sel.branches]:
            # Fields or branches changed: compare by position is meaningless and set_predicate cannot
            # express it, so it is a field change outside the contract.
            kinds.add("field")
            reshaped = True
            continue
        for p, q in zip(b_sel.predicates, a_sel.predicates, strict=True):
            if (p.modifier, p.match_all) != (q.modifier, q.match_all):
                kinds.add("modifier")
                edits += 1
            v1, v2 = frozenset(p.values), frozenset(q.values)
            if v1 != v2:
                kinds.add("values_added" if v2 > v1 else "values_removed" if v2 < v1 else "values_changed")
                edits += 1
                big_values |= len(q.values) > 8
    within = bool(kinds) and edits <= 3 and not removed and not big_values and not reshaped
    return tuple(sorted(kinds)), edits, within


def mine(git_dir: Path, pinned: str, supported_ids: set[str]) -> tuple[list[Change], Counter[str]]:
    """Every detection-changing maintenance pair for a supported rule, plus counts of what was skipped."""
    mods = list(modifications(git_dir, pinned))
    skipped: Counter[str] = Counter()
    specs = [s for c, _, _, old, new in mods for s in (f"{c}^:{old}", f"{c}:{new}")]
    blobs = _blobs(git_dir, specs) if specs else []
    changes: list[Change] = []
    for i, (commit, date, subject, _, new) in enumerate(mods):
        before_raw, after_raw = blobs[2 * i], blobs[2 * i + 1]
        if before_raw is None or after_raw is None:
            skipped["missing_or_oversized_blob"] += 1
            continue
        try:
            before = parse_rule(before_raw.decode("utf-8"))
            after = parse_rule(after_raw.decode("utf-8"))
        except (Rejected, UnicodeDecodeError):
            skipped["outside_supported_subset"] += 1
            continue
        rule_id = after.rule_id or ""
        if rule_id not in supported_ids:
            skipped["rule_not_supported_at_pin"] += 1
            continue
        if before.selections == after.selections and before.condition == after.condition:
            skipped["metadata_only"] += 1
            continue
        if is_refactor(before, after):
            skipped["refactor_renamed_selections"] += 1
            continue
        kinds, edits, within = classify(before, after)
        changes.append(
            Change(commit, date, subject, new, rule_id, kinds, edits, within, before.to_yaml(), after.to_yaml())
        )
    return changes, skipped


def summarize_mining(changes: list[Change], skipped: Counter[str], pinned: str) -> dict[str, Any]:
    kinds: Counter[str] = Counter(k for c in changes for k in c.kinds)
    return {
        "schema_version": 1,
        "pinned_commit": pinned,
        "detection_changes": len(changes),
        "rules": len({c.rule_id for c in changes}),
        "within_contract": sum(c.within_contract for c in changes),
        "kinds": dict(sorted(kinds.items())),
        "edits": dict(sorted(Counter(min(c.edits, 6) for c in changes).items())),
        "skipped": dict(sorted(skipped.items())),
    }


def to_record(change: Change) -> dict[str, Any]:
    return asdict(change)


def verify_all(
    root: Path, changes: list[dict[str, Any]], malicious_otrf: set[str], es: Elasticsearch
) -> dict[str, Any]:
    """Check every mined pair against the global pool of verified positives, in one index.

    The pool holds every SigmaHQ regression event (real attack recordings) and every OTRF event a
    reviewer labeled malicious. A pair is *verified* when the fix detects a pool event that the
    earlier version misses. The result holds ids only."""
    pool = [
        p
        for p in [*sigma_events(root / "sigma"), *otrf_events(root / "otrf")]
        if p.pool == "sigma" or p.event.event_id in malicious_otrf
    ]
    events = [Event(p.event.event_id, "malicious", None, to_ecs(p.event.data)) for p in pool]
    verdicts: Counter[str] = Counter()
    verified: list[dict[str, Any]] = []
    with es.replay_index(events) as index:
        for i, change in enumerate(changes):
            try:
                fixed = _matched(es, index, parse_rule(change["after"]), HEALTHY)
                broken = _matched(es, index, parse_rule(change["before"]), HEALTHY)
            except Rejected as exc:
                verdicts[f"engine:{exc.reason}"] += 1
                continue
            gained = sorted(fixed - broken)
            if not fixed:
                verdicts["fix_detects_no_positive"] += 1
            elif not gained:
                verdicts["not_a_coverage_fix"] += 1
            else:
                verdicts["verified"] += 1
                verified.append(
                    {"change": i, "rule_id": change["rule_id"], "commit": change["commit"], "positives": gained}
                )
    return {
        "schema_version": 1,
        "pool_events": len(events),
        "verdicts": dict(sorted(verdicts.items())),
        "verified": verified,
        "verified_rules": len({v["rule_id"] for v in verified}),
    }


def extra_roots(verified: dict[str, Any]) -> dict[str, list[str]]:
    """Rule id -> pool events that verified natural fixes newly detect, for the split builder."""
    out: dict[str, set[str]] = {}
    for v in verified["verified"]:
        out.setdefault(v["rule_id"], set()).update(v["positives"])
    return {k: sorted(v) for k, v in out.items()}


def build(
    root: Path,
    changes: list[dict[str, Any]],
    verified: dict[str, Any],
    manifest: dict[str, Any],
    report: dict[str, Any],
    *,
    benign: set[str],
    seed: str,
    malicious: set[str] | None = None,
) -> dict[str, Any]:
    """Write a case for every verified pair whose root is in the train, development or test split.

    A case only uses positives its root owns in the manifest (positive events are exclusive to one
    split), and background negatives exclude every known positive."""
    split_of = {r["id"]: (s, r) for s, groups in manifest["splits"].items() for g in groups for r in g["rules"]}
    excluded = known_positives(manifest, malicious or set())
    pool = {p.event.event_id: p for p in [*sigma_events(root / "sigma"), *otrf_events(root / "otrf")]}
    otrf_ids = sorted(k for k, p in pool.items() if p.pool == "otrf")
    out = root / "benchmark" / "cases"
    placement: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    per_split: Counter[str] = Counter()
    for v in verified["verified"]:
        change = changes[v["change"]] if v["change"] < len(changes) else {}
        if change.get("commit") != v["commit"] or change.get("rule_id") != v["rule_id"]:
            raise ValueError("natural-verified.json does not match changes.jsonl; re-run natural-verify")
        placed = split_of.get(v["rule_id"])
        if placed is None or placed[0] == "reserve":
            placement["root_not_in_split"] += 1
            continue
        split, entry = placed
        owned = [e for e in v["positives"] if e in set(entry["positive_event_ids"])]
        if not owned:
            placement["positives_owned_by_other_split"] += 1
            continue
        before, after = parse_rule(change["before"]), parse_rule(change["after"])
        matched = set(report["per_rule"].get(v["rule_id"], {}).get("matched_event_ids", []))
        background = background_negatives(otrf_ids, matched, excluded, v["rule_id"], seed)
        negatives = [pool[e] for e in sorted(matched & benign)] + [pool[e] for e in background]
        events = fixtures(v["rule_id"], [pool[e] for e in owned], negatives)
        variant = Variant(
            "natural",
            before,
            HEALTHY,
            tuple(events),
            f"SigmaHQ {change['commit'][:10]} ({change['date'][:10]}): {change['subject'][:120]}",
            {"outcome": "repaired", "family": "logic"},
        )
        case_id = f"{v['rule_id']}-natural-{change['commit'][:10]}"
        write_case(out, v["rule_id"], split, variant, after, case_id=case_id, provenance="natural")
        placement["written"] += 1
        kinds.update(change["kinds"])
        per_split[split] += 1
    return {
        "schema_version": 1,
        "placement": dict(sorted(placement.items())),
        "cases_by_split": dict(sorted(per_split.items())),
        "case_change_kinds": dict(sorted(kinds.items())),
    }
