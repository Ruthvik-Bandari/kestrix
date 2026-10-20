# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""PrimeVul-style relabelling of fix-commit functions (``docs/research/code-vuln-ml-plan.md``).

A function changed by a fix commit is labelled vulnerable only when

* **OneFunc**: it is the only function the commit changed (functions in test, vendored,
  bundled, minified and generated files are not counted; ``onefunc_strict`` reports the count
  with them), or
* **NVDCheck**: a description of one of the commit's CVEs names the function, or names its file
  while it is the only function changed in that file (PrimeVul's file rule).

Every other changed function is ``uncertain`` and excluded. The version before the fix is the
vulnerable candidate; the version after it is the patched counterpart (``None`` when the fix
deleted the function).

CVEfixes and MoreFixes record a function as changed before the fix only if a *deleted* line
falls inside it, and after the fix only if an *added* line does. A fix that only adds a check
therefore has no before-fix row. The unified diff maps line numbers between the two file
versions, so the missing side is cut from the file's full text and checked to contain the
function's name.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .paths import content_reason, path_reason, size_reason
from .qc import fix_commits_sql, sven_rows

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
SOURCE_PRIORITY = ("sven", "cvefixes", "morefixes")
MAX_METHOD_CHARS = 200_000


# --- unified diff line mapping ------------------------------------------------------------


@dataclass
class Hunk:
    old_first: int
    old_next: int
    new_first: int
    new_next: int
    new_to_old: dict[int, int] = field(default_factory=dict)


def parse_hunks(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    current: Hunk | None = None
    old = new = 0
    for line in diff.splitlines():
        m = HUNK.match(line)
        if m:
            o_start, o_len = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            n_start, n_len = int(m.group(3)), int(m.group(4) if m.group(4) is not None else 1)
            old = o_start if o_len else o_start + 1
            new = n_start if n_len else n_start + 1
            current = Hunk(old, old + o_len, new, new + n_len)
            hunks.append(current)
            continue
        if current is None or line.startswith("\\"):
            continue
        if line.startswith("+"):
            new += 1
        elif line.startswith("-"):
            old += 1
        else:
            current.new_to_old[new] = old
            old += 1
            new += 1
    return hunks


class LineMap:
    """Maps unchanged lines between the two versions of a file; changed lines map to None."""

    def __init__(self, diff: str) -> None:
        self.hunks = parse_hunks(diff)
        self.old_to_new_ctx = [{o: n for n, o in h.new_to_old.items()} for h in self.hunks]

    def new_to_old(self, line: int) -> int | None:
        shift = 0
        for h in self.hunks:
            if line < h.new_first:
                break
            if line < h.new_next:
                return h.new_to_old.get(line)
            shift = h.old_next - h.new_next
        return line + shift

    def old_to_new(self, line: int) -> int | None:
        shift = 0
        for h, ctx in zip(self.hunks, self.old_to_new_ctx, strict=True):
            if line < h.old_first:
                break
            if line < h.old_next:
                return ctx.get(line)
            shift = h.new_next - h.old_next
        return line + shift


def map_span(
    start: int, end: int, lines: LineMap, *, forward: bool, own_len: int, other_len: int
) -> tuple[int, int] | None:
    """Span of the same function in the other version, or None if every line of it changed.

    Recorded line numbers are clamped to the function's own file, so a corrupt ``end_line`` cannot
    turn into a scan over millions of lines.
    """
    to = lines.old_to_new if forward else lines.new_to_old
    end = min(end, own_len)
    if start < 1 or start > end:
        return None
    if all(to(n) is None for n in range(start, end + 1)):
        return None
    first = to(start)
    if first is None:  # the first line changed: begin after the last unchanged line before the span
        prev = next((m for m in (to(n) for n in range(start - 1, 0, -1)) if m is not None), 0)
        first = prev + 1
    last = to(end)
    if last is None:  # the last line changed: end before the first unchanged line after the span
        follow = next((m for m in (to(n) for n in range(end + 1, end + 2000)) if m is not None), other_len + 1)
        last = follow - 1
    return (first, min(last, other_len)) if first <= last else None


def short_name(name: str) -> str:
    return re.split(r"\.|::", name)[-1]


def cut(text: str | None, span: tuple[int, int] | None, name: str) -> str | None:
    """Lines ``span`` of ``text`` if they still contain the function's name."""
    if text is None or span is None:
        return None
    code = "\n".join(text.splitlines()[span[0] - 1 : span[1]]).strip("\n")
    return code if code and short_name(name) in code else None


# --- functions changed in one file --------------------------------------------------------


@dataclass
class Change:
    name: str
    before: str | None
    after: str | None
    kind: str  # paired | before_reconstructed | after_reconstructed | deleted | added | unrecoverable


@dataclass
class Method:
    name: str
    start: int
    end: int
    code: str


def file_changes(
    before_rows: list[Method], after_rows: list[Method], diff: str, code_before: str | None, code_after: str | None
) -> list[Change]:
    """Pair before/after rows of one changed file, recovering a missing side from the diff."""
    lines = LineMap(diff or "")
    old_len = len((code_before or "").splitlines())
    new_len = len((code_after or "").splitlines())
    used: set[int] = set()
    out: list[Change] = []
    for a in after_rows:
        span = (
            map_span(a.start, a.end, lines, forward=False, own_len=new_len, other_len=old_len)
            if code_before is not None
            else None
        )
        match = None
        if span is not None:
            for i, b in enumerate(before_rows):
                if i not in used and b.name == a.name and b.start <= span[1] and span[0] <= b.end:
                    match = i
                    break
        if match is not None:
            used.add(match)
            out.append(Change(a.name, before_rows[match].code, a.code, "paired"))
        elif span is None:
            out.append(Change(a.name, None, a.code, "added"))
        else:
            before = cut(code_before, span, a.name)
            out.append(Change(a.name, before, a.code, "before_reconstructed" if before else "unrecoverable"))
    for i, b in enumerate(before_rows):
        if i in used:
            continue
        span = (
            map_span(b.start, b.end, lines, forward=True, own_len=old_len, other_len=new_len)
            if code_after is not None
            else None
        )
        if span is None:
            out.append(Change(b.name, b.code, None, "deleted"))
            continue
        after = cut(code_after, span, b.name)
        out.append(Change(b.name, b.code, after, "after_reconstructed" if after else "unrecoverable"))
    return out


# --- NVDCheck -------------------------------------------------------------------------------

CODE_CONTEXT = (
    r"(?<![\w$.]){n}\s*\(",
    r"[`'\"]{n}[`'\"(]",
    r"\.{n}(?![\w$])",
    r"(?<![\w$]){n}\s+(?:function|method)\b",
    r"\b(?:function|method)\s+[`'\"]?{n}(?![\w$])",
)


def mentions_function(description: str, name: str) -> bool:
    """Does the description name this function?

    Identifier-like names (with ``_``, digits or inner capitals) match as whole words. A plain
    lowercase word such as ``parse`` or ``render`` also reads as English, so it must appear in a
    code context: a call, quotes or backticks, an attribute, or next to "function"/"method".
    """
    short = short_name(name)
    if len(short) < 3 or not re.fullmatch(r"[\w$]+", short):
        return False
    n = re.escape(short)
    if "." in name and re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", description):
        return True
    if re.search(r"[_\d$]|[a-z][A-Z]", short) or short[0].isupper():
        return bool(re.search(rf"(?<![\w$]){n}(?![\w$])", description))
    return any(re.search(p.format(n=n), description) for p in CODE_CONTEXT)


def mentions_file(description: str, path: str) -> bool:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return bool(base) and bool(re.search(rf"(?<![\w$.-]){re.escape(base)}(?![\w$])", description))


# --- per-commit labelling -------------------------------------------------------------------


@dataclass
class FileUnits:
    path: str
    language: str
    reason: str | None
    changes: list[Change]  # empty for an excluded file: its functions are only counted
    excluded_functions: int = 0


def label_commit(
    files: list[FileUnits], other_counted: int, descriptions: list[str]
) -> Iterator[tuple[FileUnits, Change, str]]:
    """Yield (file, change, label) for every change in a kept file; label is a rule name or ``uncertain``."""
    counted = sum(len(f.changes) for f in files if f.reason is None) + other_counted
    for f in files:
        if f.reason is not None:
            continue
        for change in f.changes:
            if counted == 1:
                yield f, change, "onefunc"
            elif any(mentions_function(d, change.name) for d in descriptions):
                yield f, change, "nvd_name"
            elif len(f.changes) == 1 and any(mentions_file(d, f.path) for d in descriptions):
                yield f, change, "nvd_file"
            else:
                yield f, change, "uncertain"


def record_id(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:24]


def repo_key(url: str) -> str:
    """``host/owner/name`` lower-cased, e.g. ``github.com/django/django``."""
    stripped = re.sub(r"^https?://", "", url.strip().rstrip("/")).removesuffix(".git")
    return "/".join(stripped.split("/")[:3]).lower()


class Stats:
    def __init__(self) -> None:
        self.c: dict[str, Counter[str]] = defaultdict(Counter)

    def add(self, source: str, language: str, key: str, n: int = 1) -> None:
        self.c[f"{source}/{language}"][key] += n

    def as_dict(self) -> dict[str, dict[str, int]]:
        return {k: dict(sorted(v.items())) for k, v in sorted(self.c.items())}


def _cve_maps(db: sqlite3.Connection) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
    published: dict[str, str] = {}
    descriptions: dict[str, str] = {}
    for cve_id, date, desc in db.execute("SELECT cve_id, published_date, description FROM cve"):
        if date and (cve_id not in published or date < published[cve_id]):
            published[cve_id] = str(date)
        if desc:
            descriptions[cve_id] = str(desc)
    cwes: dict[str, list[str]] = defaultdict(list)
    for cve_id, cwe in db.execute("SELECT DISTINCT cve_id, cwe_id FROM cwe_classification"):
        cwes[cve_id].append(str(cwe))
    return published, descriptions, cwes


def ghsa_aliases(root: Path) -> tuple[dict[str, set[str]], dict[str, str]]:
    """{CVE or GHSA id: the ids it is linked to}, {id: GHSA published date} from ``work/ghsa.jsonl``."""
    links: dict[str, set[str]] = defaultdict(set)
    dates: dict[str, str] = {}
    path = root / "work" / "ghsa.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines() if path.exists() else []:
        r = json.loads(line)
        ids = {r["id"], *r["aliases"]}
        for i in ids:
            links[i] |= ids
            if r["published"]:
                dates.setdefault(i, str(r["published"]))
    return links, dates


def commit_files(db: sqlite3.Connection, sha: str, source: str, stats: Stats) -> list[FileUnits]:
    """The commit's changed Python/JS/TS files with their changed functions (excluded files: counts only)."""
    rows = db.execute(  # streamed: one commit can carry gigabytes of bundled JavaScript
        "SELECT file_change_id, coalesce(new_path, old_path, filename), language, diff, code_before, code_after "
        "FROM file_change WHERE hash = ? ORDER BY file_change_id",
        (sha,),
    )
    files: list[FileUnits] = []
    seen_paths: set[str] = set()
    for fc_id, path, language, diff, code_before, code_after in rows:
        if path in seen_paths:  # the same commit mirrored in a fork
            continue
        seen_paths.add(path)
        stats.add(source, language, "files")
        reason = path_reason(path) or content_reason(code_before) or content_reason(code_after)
        if reason:  # not a candidate location: count its changed functions, never load their code
            stats.add(source, language, f"file_excluded:{reason}")
            (count,) = db.execute(
                "SELECT count(DISTINCT name) FROM method_change WHERE file_change_id = ? AND name IS NOT NULL",
                (fc_id,),
            ).fetchone()
            files.append(FileUnits(path, language, reason, [], count))
            continue
        # A lizard "method" in a one-line file is the whole line, so code over MAX_METHOD_CHARS (far
        # beyond the 400-line limit) is never loaded; such a function keeps its row but no text.
        methods = db.execute(
            "SELECT name, start_line, end_line, CASE WHEN length(code) > ? THEN '' ELSE code END, before_change "
            "FROM method_change WHERE file_change_id = ? AND name IS NOT NULL AND start_line IS NOT NULL",
            (MAX_METHOD_CHARS, fc_id),
        ).fetchall()
        before = [Method(n, s, e, c or "") for n, s, e, c, b in methods if b]
        after = [Method(n, s, e, c or "") for n, s, e, c, b in methods if not b]
        files.append(FileUnits(path, language, None, file_changes(before, after, diff, code_before, code_after)))
    return files


def source_candidates(
    db: sqlite3.Connection, source: str, stats: Stats, links: dict[str, set[str]], ghsa_dates: dict[str, str]
) -> Iterator[dict[str, Any]]:
    published, descriptions, cwes = _cve_maps(db)
    by_commit: dict[str, tuple[set[str], set[str]]] = defaultdict(lambda: (set(), set()))
    for cve_id, sha, url in db.execute(fix_commits_sql(source)):
        by_commit[sha][0].add(str(cve_id))
        by_commit[sha][1].add(str(url))
    commits = sorted(h for (h,) in db.execute("SELECT DISTINCT hash FROM file_change") if h in by_commit)
    for sha in commits:
        cve_ids, urls = by_commit[sha]
        files = commit_files(db, sha, source, stats)
        other = db.execute("SELECT path, functions FROM other_functions WHERE hash = ?", (sha,)).fetchall()
        other_all = sum(n for _, n in other)
        other_counted = sum(n for p, n in other if path_reason(p) is None)
        all_units = sum(len(f.changes) + f.excluded_functions for f in files) + other_all
        descs = [descriptions[c] for c in sorted(cve_ids) if c in descriptions]
        ids = set(cve_ids)
        for c in cve_ids:
            ids |= links.get(c, set())
        dates = [d for c in ids for d in (published.get(c), ghsa_dates.get(c)) if d]
        for f, change, label in label_commit(files, other_counted, descs):
            stats.add(source, f.language, f"functions_changed:{change.kind}")
            stats.add(source, f.language, f"label:{label}")
            if label == "onefunc" and all_units == 1:
                stats.add(source, f.language, "onefunc_strict")
            if label == "uncertain" and any(mentions_file(d, f.path) for d in descs):
                stats.add(source, f.language, "uncertain_but_file_named_with_other_functions")
            if label == "uncertain":
                continue
            if change.before is None:
                stats.add(source, f.language, f"vulnerable_dropped:no_before_version_{change.kind}")
                continue
            size = size_reason(change.before)
            if size:
                stats.add(source, f.language, f"vulnerable_dropped:{size}")
                continue
            stats.add(source, f.language, "vulnerable_kept")
            stats.add(source, f.language, "with_patched_counterpart" if change.after else "without_patched_counterpart")
            repos = sorted({repo_key(u) for u in urls})
            yield {
                "id": record_id(source, sha, f.path, change.name, change.before),
                "source": source,
                "repo": repos[0],
                "repos": repos,
                "commit": sha,
                "cve_ids": sorted(c for c in ids if c.startswith("CVE-")),
                "advisory_ids": sorted(ids),
                "cwes": sorted({w for c in cve_ids for w in cwes.get(c, [])}),
                "published": min(dates)[:10] if dates else None,
                "language": f.language,
                "path": f.path,
                "function": change.name,
                "label_rule": label,
                "pair_kind": change.kind,
                "vulnerable": change.before,
                "patched": change.after,
            }


def sven_candidates(root: Path, stats: Stats) -> Iterator[dict[str, Any]]:
    for split, row in sven_rows(root / "raw" / "sven"):
        path = str(row.get("file_name", ""))
        if not path.endswith(".py"):
            continue
        stats.add("sven", "python", "pairs")
        before, after = str(row.get("func_src_before", "")), str(row.get("func_src_after", ""))
        reason = path_reason(path) or size_reason(before)
        if reason:
            stats.add("sven", "python", f"vulnerable_dropped:{reason}")
            continue
        link = str(row.get("commit_link", ""))
        repo_part, _, sha = link.partition("/commit/")
        stats.add("sven", "python", "vulnerable_kept")
        yield {
            "id": record_id("sven", link, path, row.get("func_name"), before),
            "source": "sven",
            "repo": repo_key(repo_part),
            "repos": [repo_key(repo_part)],
            "commit": sha,
            "cve_ids": [],
            "advisory_ids": [],
            "cwes": [str(row.get("vul_type", "")).upper()],
            "published": None,
            "language": "python",
            "path": path,
            "function": str(row.get("func_name", "")),
            "label_rule": "sven",
            "pair_kind": "paired",
            "sven_split": split,
            "vulnerable": before,
            "patched": after,
        }


def run(root: Path) -> dict[str, Any]:
    links, ghsa_dates = ghsa_aliases(root)
    stats = Stats()
    out = root / "work" / "candidates.jsonl"
    tmp = out.with_name(out.name + ".tmp")
    kept: Counter[str] = Counter()
    with tmp.open("w", encoding="utf-8") as fh:
        for record in sven_candidates(root, stats):
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            kept[f"sven/{record['language']}"] += 1
        for source in ("cvefixes", "morefixes"):
            db = sqlite3.connect(root / "work" / f"{source}.sqlite")
            for record in source_candidates(db, source, stats, links, ghsa_dates):
                fh.write(json.dumps(record, sort_keys=True) + "\n")
                kept[f"{source}/{record['language']}"] += 1
            db.close()
    tmp.chmod(0o600)
    tmp.replace(out)
    return {
        "schema_version": 1,
        "rules": {
            "onefunc": "only function changed by the fix commit (test/vendor/dist/minified/generated files not counted)",
            "nvd_name": "a CVE description names the function (code context required for plain English words)",
            "nvd_file": "a CVE description names the file and the function is the only one changed in it",
            "uncertain": "any other changed function; excluded",
        },
        "label_accuracy_caveat": "Rule-based labels. PrimeVul reports 86-92% accuracy for these rules on C/C++; "
        "no hand audit has been done here yet (the plan requires at least 200 samples before training).",
        "candidates": dict(sorted(kept.items())),
        "per_source_language": stats.as_dict(),
    }
