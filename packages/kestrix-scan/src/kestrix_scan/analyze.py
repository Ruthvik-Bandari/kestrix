# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Scan files for insecure code and hard-coded secrets.

Order of operations for each file: read as bytes and decode, run the Python rules (``.py``
files) and the secret rules (every text file), drop findings covered by an inline suppression
that gives a reason, then, across the scan, drop findings outside the ``--diff`` lines and
findings whose fingerprint is in the baseline.

JavaScript and TypeScript files (``JS_SUFFIXES``) get the ``js.*`` rules where Python files get the ``py.*`` rules.
HTML, Vue, Svelte and Angular templates take ``<!-- kestrix: ignore[...] reason -->``; CSS takes ``/* ... */``.
A ``/* kestrix: ignore[...] reason */`` block comment (``{/* ... */}`` in JSX) suppresses like a line comment.

Suppression: ``# kestrix: ignore[rule-id] reason`` (or ``// kestrix: ignore[...] reason``) on the
finding's line or the line above; several ids may be separated by commas. A suppression without
a reason suppresses nothing and adds a ``kestrix.suppression.missing_reason`` note to the report.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Literal

from . import deps
from .agent_config import check_config, config_kind
from .config import FAIL_ON_CHOICES, Config
from .errors import Reason, Rejected
from .js_rules import JS_SUFFIXES, check_js
from .models import SEVERITY_RANK, Finding, Note, ScanReport, SkippedFile, count, fingerprint, ordered
from .python_rules import check_python
from .registry import RULES, Hit
from .secrets import check_secrets, redact
from .walk import MAX_FILE_BYTES, Candidate, Unreadable, collect, file_limit, git_executable, is_within, read_text
from .web_rules import WEB_SUFFIXES, check_web

FailOn = Literal["low", "medium", "high", "critical", "none"]
MAX_BASELINE_BYTES = 10 * 1024 * 1024
PYTHON_SUFFIXES = frozenset({".py", ".pyw"})
MISSING_REASON = "kestrix.suppression.missing_reason"

_SUPPRESSION = re.compile(r"(?:#|//|/\*|<!--)\s*kestrix:\s*ignore\[([^\]\n]*)\]([^\n]*)")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_GIT_TIMEOUT_S = 30
_CONFIG_SECRET_RULES = frozenset({"config.mcp.secret_inline", "config.claude.env_leak"})


def scan(
    paths: Sequence[str | Path] = (".",),
    *,
    config: Config | None = None,
    root: str | Path | None = None,
    fail_on: FailOn | None = None,
    baseline: str | Path | None = None,
    diff_base: str | None = None,
) -> ScanReport:
    """Scan ``paths`` and return a report. Raises ``Rejected`` for missing paths, a bad baseline or a bad diff base.

    ``config``: settings such as ``kestrix_scan.load_config(root)`` returns (rules, excludes,
    ``fail-on`` and baseline); the explicit arguments below override it. ``root``: directory that
    finding paths are relative to; by default the current directory when every path is inside it,
    otherwise the paths' common parent. ``fail_on`` (default ``high``) is recorded in the report and
    used by ``exit_code``. ``baseline``: JSON list of fingerprints to leave out. ``diff_base``: git
    ref; only findings on lines changed since it are kept.
    """
    started = time.perf_counter()
    settings = config or Config()
    level = fail_on or settings.fail_on or "high"
    if level not in FAIL_ON_CHOICES:
        raise Rejected(Reason.INVALID_INPUT, f"--fail-on must be one of {', '.join(FAIL_ON_CHOICES)}")
    baseline = baseline if baseline is not None else settings.baseline
    scan_root, targets = resolve_targets(paths, root)
    known = load_baseline(Path(baseline)) if baseline is not None else frozenset()
    changes = changed_lines(scan_root, diff_base) if diff_base is not None else None
    active = settings.active_rules() if settings.enable or settings.disable else None

    walk = collect(targets, scan_root)
    if settings.exclude:
        walk.candidates = [c for c in walk.candidates if not settings.excluded(c.rel)]
        walk.skipped = [s for s in walk.skipped if not settings.excluded(s.path)]
    findings: list[Finding] = []
    notes: list[Note] = []
    skipped = list(walk.skipped)
    suppressed = 0
    scanned = 0
    ignored_advisories = dict(settings.ignore_advisories)
    first_dependency_file: str | None = None
    for candidate in walk.candidates:
        try:
            text = read_text(candidate, file_limit(candidate.rel))
        except Unreadable as exc:
            skipped.append(SkippedFile(path=candidate.rel, reason=exc.reason))
            continue
        scanned += 1
        if first_dependency_file is None and deps.is_dependency_file(candidate.rel):
            first_dependency_file = candidate.rel
        file_findings, file_notes, file_suppressed, skip = scan_text(text, candidate, active, ignored_advisories)
        findings.extend(file_findings)
        notes.extend(file_notes)
        suppressed += file_suppressed
        if skip is not None:
            skipped.append(skip)

    if (
        first_dependency_file is not None
        and (stale := deps.stale_note(first_dependency_file, settings.db_max_age_days)) is not None
    ):
        notes.append(stale)
    if changes is not None:
        findings = [finding for finding in findings if _changed(finding, changes)]
    kept = [finding for finding in findings if finding.fingerprint not in known]
    return ScanReport(
        root=scan_root.as_posix(),
        diff_base=diff_base,
        fail_on=level,
        files_scanned=scanned,
        files_skipped=sorted(skipped, key=lambda item: item.path),
        truncated=walk.truncated,
        findings=ordered(kept),
        counts=count(kept),
        suppressed=suppressed,
        baseline_filtered=len(findings) - len(kept),
        notes=sorted(notes, key=lambda note: (note.path, note.line)),
        duration_ms=round((time.perf_counter() - started) * 1000),
    )


def scan_text(
    text: str,
    candidate: Candidate,
    active: frozenset[str] | None = None,
    ignore_advisories: Mapping[str, str] | None = None,
) -> tuple[list[Finding], list[Note], int, SkippedFile | None]:
    """Findings, notes, suppressed count and an optional skip record for one decoded file.

    ``active``: the rule ids to report (``None``: every rule); hits of other rules are dropped first.
    ``ignore_advisories``: advisory ids (or aliases) left out of dependency findings, with their reasons.
    A dependency file is also checked against the local vulnerability index; one over 1 MiB gets only that check.
    """
    hits: list[Hit] = []
    skip = None
    if candidate.path.suffix in PYTHON_SUFFIXES:
        result = check_python(text, candidate.rel)
        if isinstance(result, list):
            hits.extend(result)
        else:
            skip = SkippedFile(path=candidate.rel, reason=result)
    elif candidate.path.suffix in JS_SUFFIXES:
        result = check_js(text, candidate.rel)
        if isinstance(result, list):
            hits.extend(result)
        else:
            skip = SkippedFile(path=candidate.rel, reason=result)
    elif candidate.path.suffix.lower() in WEB_SUFFIXES:
        result = check_web(text, candidate.rel)
        if isinstance(result, list):
            hits.extend(result)
        else:
            skip = SkippedFile(path=candidate.rel, reason=result)
    elif config_kind(candidate.rel) is not None:
        result = check_config(text, candidate.rel)
        if isinstance(result, list):
            hits.extend(result)
        else:
            skip = SkippedFile(path=candidate.rel, reason=result)
    dependency_file = deps.is_dependency_file(candidate.rel)
    if not dependency_file or len(text) <= MAX_FILE_BYTES:
        hits.extend(check_secrets(text))
    if active is not None:
        hits = [item for item in hits if item.rule_id in active]
    config_secret_lines = {item.line for item in hits if item.rule_id in _CONFIG_SECRET_RULES}
    if config_secret_lines:  # one finding per credential: the config rule names where it sits
        hits = [i for i in hits if not (i.rule_id.startswith("secret.") and i.line in config_secret_lines)]
    suppressions, notes = _suppressions(text, candidate.rel)
    findings: list[Finding] = []
    suppressed = 0
    if dependency_file:
        dep_findings, dep_notes, suppressed = deps.check_file(
            text, candidate.rel, suppressions, active, ignore_advisories or {}
        )
        findings.extend(dep_findings)
        notes.extend(dep_notes)
    for item in hits:
        ids_here = suppressions.get(item.line, frozenset()) | suppressions.get(item.line - 1, frozenset())
        if item.rule_id in ids_here:
            suppressed += 1
            continue
        findings.append(_finding(item, candidate.rel))
    return findings, notes, suppressed, skip


def _finding(item: Hit, rel: str) -> Finding:
    rule = RULES[item.rule_id]
    snippet = item.snippet if item.rule_id.startswith("secret.") else redact(item.snippet)
    return Finding(
        rule_id=rule.id,
        cwe=item.cwe or rule.cwe,
        severity=item.severity or rule.severity,
        confidence=item.confidence or rule.confidence,
        path=rel,
        line=item.line,
        column=item.column,
        end_line=max(item.end_line, item.line),
        message=item.message,
        why=rule.why,
        fix=rule.fix,
        snippet=snippet[:200],
        fingerprint=fingerprint(rule.id, rel, snippet),
        trace=item.trace,
    )


def _suppressions(text: str, rel: str) -> tuple[dict[int, frozenset[str]], list[Note]]:
    """Rule ids suppressed per line (only suppressions that give a reason), and notes for the others."""
    by_line: dict[int, frozenset[str]] = {}
    notes: list[Note] = []
    if "kestrix:" not in text:
        return by_line, notes
    for number, line in enumerate(text.splitlines(), start=1):
        match = _SUPPRESSION.search(line)
        if match is None:
            continue
        ids = frozenset(part.strip() for part in match.group(1).split(",") if part.strip())
        reason = match.group(2).strip().removesuffix("-->").removesuffix("*/").strip()
        if any(char.isalnum() for char in reason):
            by_line[number] = ids
        else:
            notes.append(
                Note(
                    id=MISSING_REASON,
                    path=rel,
                    line=number,
                    message="This kestrix: ignore[...] comment has no reason, so it suppresses nothing. Add why the finding is safe.",
                )
            )
    return by_line, notes


def exit_code(report: ScanReport, fail_on: FailOn | None = None) -> int:
    """0 when no finding is at or above ``fail_on`` (default: the report's), else 1. 'none' never fails."""
    threshold = fail_on or report.fail_on
    if threshold == "none":
        return 0
    return 1 if any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[threshold] for f in report.findings) else 0


def resolve_targets(paths: Sequence[str | Path], root: str | Path | None) -> tuple[Path, list[Path]]:
    """The scan root and the absolute targets. The final path component is kept unresolved so links stay links."""
    if not paths:
        paths = (".",)
    targets = []
    for raw in paths:
        absolute = Path(os.path.abspath(raw))
        target = absolute.parent.resolve() / absolute.name if absolute.name else absolute.resolve()
        if not os.path.lexists(target):
            raise Rejected(Reason.INVALID_INPUT, f"path not found: {raw}")
        targets.append(target)
    if root is not None:
        scan_root = Path(root).resolve()
        if not scan_root.is_dir():
            raise Rejected(Reason.INVALID_INPUT, f"root is not a directory: {root}")
    else:
        cwd = Path.cwd().resolve()
        if all(is_within(target, cwd) for target in targets):
            scan_root = cwd
        else:
            dirs = [t if t.is_dir() and not t.is_symlink() else t.parent for t in targets]
            scan_root = Path(os.path.commonpath(dirs))
    outside = [str(t) for t in targets if not is_within(t, scan_root)]
    if outside:
        raise Rejected(Reason.INVALID_INPUT, f"path is outside the scan root {scan_root}: {outside[0]}")
    return scan_root, targets


# ----- baseline


def load_baseline(path: Path) -> frozenset[str]:
    """Fingerprints from a baseline file: a JSON list of 64-character lowercase hex strings."""
    try:
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"baseline is larger than {MAX_BASELINE_BYTES:,} bytes")
        data = json.loads(path.read_bytes())
    except OSError as exc:
        raise Rejected(Reason.INVALID_INPUT, f"cannot read baseline {path}: {exc.strerror}") from None
    except (ValueError, RecursionError):
        raise Rejected(Reason.INVALID_INPUT, f"baseline {path} is not valid JSON") from None
    if not isinstance(data, list) or not all(isinstance(i, str) and _FINGERPRINT.fullmatch(i) for i in data):
        raise Rejected(Reason.INVALID_INPUT, f"baseline {path} must be a JSON list of SHA-256 fingerprints")
    return frozenset(data)


def write_baseline(path: Path, findings: Iterable[Finding]) -> int:
    """Atomically write the findings' fingerprints (sorted, unique) to ``path`` with mode 0644; returns the count."""
    fingerprints = sorted({finding.fingerprint for finding in findings})
    data = (json.dumps(fingerprints, indent=2) + "\n").encode()
    directory = path.parent if str(path.parent) else Path(".")
    try:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".kestrix-baseline-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise Rejected(Reason.INVALID_INPUT, f"cannot write baseline {path}: {exc.strerror}") from None
    return len(fingerprints)


# ----- diff mode

Changes = dict[str, frozenset[int] | None]  # None: every line counts as changed (untracked file)


def _git(git: str, root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # noqa: S603 - git from PATH with a fixed argument list, no shell
            [git, "-c", "core.quotepath=false", *args],
            cwd=root,
            capture_output=True,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Rejected(Reason.INVALID_INPUT, f"git failed: {exc}") from None


def changed_lines(root: Path, base: str) -> Changes:
    """Lines added or changed since ``base`` (working tree, staged or not), and untracked files as wholly new."""
    git = git_executable()
    if git is None:
        raise Rejected(Reason.INVALID_INPUT, "--diff needs git, which was not found on PATH")
    if not base or base.startswith("-"):
        raise Rejected(Reason.INVALID_INPUT, "--diff needs a git ref such as main or HEAD~1")
    if _git(git, root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        raise Rejected(Reason.INVALID_INPUT, f"--diff: {root} is not inside a git work tree")
    if _git(git, root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}").returncode != 0:
        raise Rejected(Reason.INVALID_INPUT, f"--diff: unknown git ref {base!r}")
    diff = _git(
        git,
        root,
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        "--relative",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base,
        "--",
    )
    if diff.returncode != 0:
        raise Rejected(Reason.INVALID_INPUT, f"--diff: git diff against {base!r} failed")
    changes = parse_diff(diff.stdout.decode("utf-8", "replace"))
    untracked = _git(git, root, "ls-files", "-z", "--others", "--exclude-standard")
    for name in untracked.stdout.decode("utf-8", "replace").split("\0"):
        if name:
            changes[name] = None
    return changes


def parse_diff(text: str) -> Changes:
    """Added line numbers per file from ``git diff --unified=0`` output."""
    lines: dict[str, set[int]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].rstrip("\t")
            if target.startswith('"') and target.endswith('"'):
                target = target[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            current = target[2:] if target.startswith("b/") else None
            if current is not None:
                lines.setdefault(current, set())
        elif line.startswith("@@") and current is not None and (match := _HUNK.match(line)):
            start = int(match.group(1))
            length = int(match.group(2)) if match.group(2) is not None else 1
            lines[current].update(range(start, start + length))
    return {name: frozenset(numbers) for name, numbers in lines.items()}


def _changed(finding: Finding, changes: Changes) -> bool:
    if finding.path not in changes:
        return False
    numbers = changes[finding.path]
    return numbers is None or any(n in numbers for n in range(finding.line, finding.end_line + 1))
