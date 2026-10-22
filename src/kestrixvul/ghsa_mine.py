# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Mine the GitHub Advisory Database fix commits that CVEfixes and MoreFixes do not cover.

Three stages, each resumable:

1. ``targets`` (Slurm, offline): reviewed, non-withdrawn PyPI and npm advisories from the pinned
   GHSA checkout; each cited ``github.com/<owner>/<name>/commit/<sha>`` that neither working
   database holds as a fix commit with a Python/JS/TS change becomes a target (role ``ghsa``).
   Every commit of the existing split is a target too (role ``pool``), only to sample negatives
   from its parent snapshot. Writes the private ``work/mine_targets.jsonl`` and
   ``work/ghsa_text.jsonl`` (advisory summary, details and linked CVE descriptions).
2. ``fetch`` (transfer node, standard library only): per repository, an anonymous HTTPS partial
   clone into a bare repository: ``git fetch --filter=blob:none --depth=2 origin <sha>`` brings the
   fix commit, its parent and their trees; then one ``git fetch`` of exactly the blobs needed (the
   changed Python/JS/TS files that pass the path filters, before and after, plus up to
   ``SAMPLED_FILES`` unchanged files of the parent snapshot for negatives). No GitHub API call is
   made. A global limiter starts at most one git network request per ``interval`` seconds, a
   transient error pushes every worker back (exponential backoff), each git call has a timeout,
   and a repository whose object store grows past ``max_bytes`` is abandoned. The file texts go to
   ``mine/commits/<sha>.json.gz`` (0600) and the bare repository is deleted. A commit with an output
   file or a permanent failure in ``mine/status.jsonl`` is skipped on the next run.
3. ``extract`` (Slurm, offline): functions before and after (``functions.py``), the same file filters
   and PrimeVul rules as ``labels.py`` (descriptions: the advisory text), giving
   ``work/ghsa_candidates.jsonl``; unchanged functions of the parent snapshot go to
   ``work/negative_candidates.jsonl``. Reports hold counts only.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .functions import Func, diff_functions, functions, is_other_code, language_of
from .labels import FileUnits, label_commit, record_id, repo_key
from .paths import content_reason, path_reason, size_reason
from .qc import COMMIT_URL, MAX_ADVISORY_BYTES, TARGET, fix_commits_sql, hashes_by_prefix

REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SAMPLED_FILES = 3
BLOB_CHUNK = 256
MAX_BLOB_BYTES = 2_000_000
PERMANENT = (
    "repository not found",
    "not found",
    "could not read username",
    "authentication failed",
    "not our ref",
    "unadvertised object",
    "does not exist",
    "no such remote ref",
    "couldn't find remote ref",
    "unknown revision",
)
REPO_FATAL = ("repository not found", "could not read username", "authentication failed")  # whole repository gone
SCHEMA_VERSION = 1


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


# --- stage 1: targets ------------------------------------------------------------------------


def advisory_texts(checkout: Path) -> Iterator[dict[str, Any]]:
    """Reviewed PyPI/npm advisories with their summary and details (``qc.advisories`` plus text)."""
    for path in sorted((checkout / "advisories" / "github-reviewed").rglob("*.json")):
        if path.stat().st_size > MAX_ADVISORY_BYTES:
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        ecosystems = sorted(
            {
                str(a.get("package", {}).get("ecosystem"))
                for a in doc.get("affected") or []
                if isinstance(a, dict) and a.get("package", {}).get("ecosystem") in {"PyPI", "npm"}
            }
        )
        if not ecosystems or doc.get("withdrawn"):
            continue
        commits = []
        for ref in doc.get("references") or []:
            m = COMMIT_URL.match(str(ref.get("url", ""))) if isinstance(ref, dict) else None
            if m:
                commits.append({"repo": f"{m.group(1)}/{m.group(2)}".lower(), "sha": m.group(3).lower()})
        yield {
            "id": str(doc.get("id")),
            "aliases": sorted(str(a) for a in doc.get("aliases") or []),
            "published": doc.get("published"),
            "ecosystems": ecosystems,
            "cwes": sorted(str(c) for c in (doc.get("database_specific") or {}).get("cwe_ids") or []),
            "summary": str(doc.get("summary") or ""),
            "details": str(doc.get("details") or ""),
            "commits": commits,
        }


def _fix_hashes_and_cves(db: sqlite3.Connection, source: str, cves: set[str]) -> tuple[set[str], dict[str, str]]:
    db.execute(f"CREATE TEMP TABLE fx AS {fix_commits_sql(source)}")
    db.execute("CREATE INDEX temp.fx_hash ON fx(hash)")
    hashes = {
        str(h)
        for (h,) in db.execute(
            "SELECT DISTINCT f.hash FROM file_change f JOIN fx ON fx.hash = f.hash WHERE f.language IN (?,?,?)",
            TARGET,
        )
    }
    texts: dict[str, str] = {}
    for cve_id, published, desc in db.execute("SELECT cve_id, published_date, description FROM cve"):
        if cve_id in cves and desc:
            texts[str(cve_id)] = f"{published or ''}\x1f{desc}"
    return hashes, texts


def covered(sha: str, hashes: set[str]) -> bool:
    return bool(hashes_by_prefix(hashes, sha))


def targets(root: Path) -> dict[str, Any]:
    advisories = list(advisory_texts(root / "raw" / "ghsa"))
    cves = {a for adv in advisories for a in adv["aliases"] if a.startswith("CVE-")}
    hashes: dict[str, set[str]] = {}
    cve_text: dict[str, str] = {}
    for source in ("cvefixes", "morefixes"):
        db = sqlite3.connect(root / "work" / f"{source}.sqlite")
        hashes[source], texts = _fix_hashes_and_cves(db, source, cves)
        db.close()
        for k, v in texts.items():
            cve_text.setdefault(k, v)
    text_rows = []
    for adv in advisories:
        linked = []
        dates = [str(adv["published"])[:10]] if adv["published"] else []
        for alias in adv["aliases"]:
            if alias in cve_text:
                published, desc = cve_text[alias].split("\x1f", 1)
                linked.append(desc)
                if published:
                    dates.append(published[:10])
        text_rows.append(
            {k: adv[k] for k in ("id", "aliases", "ecosystems", "cwes", "summary", "details")}
            | {"cve_descriptions": linked, "published": min(dates) if dates else None}
        )
    write_private(root / "work" / "ghsa_text.jsonl", jsonl(text_rows))

    stats: Counter[str] = Counter()
    by_commit: dict[tuple[str, str], set[str]] = defaultdict(set)
    for adv in advisories:
        for c in adv["commits"]:
            by_commit[(c["repo"], c["sha"])].add(adv["id"])
    rows: list[dict[str, Any]] = []
    for (repo, sha), ids in sorted(by_commit.items()):
        stats["ghsa_distinct_fix_commits"] += 1
        in_cvefixes, in_morefixes = covered(sha, hashes["cvefixes"]), covered(sha, hashes["morefixes"])
        stats[f"covered_by:{'+'.join(n for n, b in (('cvefixes', in_cvefixes), ('morefixes', in_morefixes)) if b) or 'neither'}"] += 1  # fmt: skip
        if in_cvefixes or in_morefixes:
            continue
        if not SHA.match(sha):
            stats["skipped_abbreviated_sha"] += 1
            continue
        if not REPO.match(repo):
            stats["skipped_bad_repo_name"] += 1
            continue
        rows.append({"repo": repo, "sha": sha, "role": "ghsa", "advisories": sorted(ids)})
    ghsa_shas = {r["sha"] for r in rows}
    pool: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(root / "work" / "split.jsonl"):
        host, _, name = record["repo"].partition("/")
        sha = str(record["commit"]).lower()
        if host != "github.com" or not REPO.match(name) or not SHA.match(sha) or sha in ghsa_shas:
            continue
        entry = pool.setdefault(sha, {"repo": name, "sha": sha, "role": "pool", "advisories": []})
        entry["advisories"] = sorted(set(entry["advisories"]) | set(record["advisory_ids"]))
    rows += [pool[s] for s in sorted(pool)]
    stats["targets_ghsa"] = len(ghsa_shas)
    stats["targets_pool"] = len(pool)
    stats["repositories"] = len({r["repo"] for r in rows})
    write_private(root / "work" / "mine_targets.jsonl", jsonl(rows))
    return {"schema_version": SCHEMA_VERSION, "stage": "targets", "counts": dict(sorted(stats.items()))}


# --- stage 2: fetch (transfer node) ----------------------------------------------------------


class GitError(RuntimeError):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class Limiter:
    """Global pacing: one git network request per ``interval`` seconds; errors push everyone back."""

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.errors = 0

    def wait(self) -> None:
        with self.lock:
            start = max(time.monotonic(), self.next_at)
            self.next_at = start + self.interval
        time.sleep(max(0.0, start - time.monotonic()))

    def failed(self) -> float:
        """Record a transient error; return the backoff that now applies to every worker."""
        with self.lock:
            self.errors += 1
            backoff = float(min(300, 5 * 2 ** min(self.errors - 1, 6)))
            self.next_at = max(self.next_at, time.monotonic() + backoff)
            return backoff

    def succeeded(self) -> None:
        with self.lock:
            self.errors = 0


@dataclass(frozen=True)
class FetchConfig:
    timeout: float = 300.0
    max_bytes: int = 500 * 1024 * 1024
    retries: int = 3
    sampled_files: int = SAMPLED_FILES
    max_changed_files: int | None = None  # keep at most this many changed files per commit (a seeded sample)


def remote_url(repo: str) -> str:
    if not REPO.match(repo):
        raise GitError("bad_repo_name", repo)
    return f"https://github.com/{repo}.git"


def _dir_bytes(path: Path) -> int:
    total = 0
    for dirpath, _, files in os.walk(path):
        for f in files:
            with contextlib.suppress(OSError):
                total += os.path.getsize(os.path.join(dirpath, f))
    return total


class Git:
    """git in one bare repository, anonymous, with a timeout and an object-store size cap."""

    def __init__(self, gitdir: Path, home: Path, config: FetchConfig) -> None:
        self.gitdir = gitdir
        self.config = config
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),  # an empty home: no user config, no credential helper
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "LC_ALL": "C",
        }

    def run(self, *args: str, stdin: bytes | None = None, network: bool = False) -> bytes:
        cmd = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.version=2",
            "-c",
            "http.lowSpeedLimit=1000",
            "-c",
            "http.lowSpeedTime=60",
            "-c",
            "core.askPass=/bin/false",
            f"--git-dir={self.gitdir}",
            *args,
        ]
        proc = subprocess.Popen(  # noqa: S603 - fixed git argument list, repository names validated
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
        )
        deadline = time.monotonic() + self.config.timeout
        payload = stdin
        while True:
            try:
                out, err = proc.communicate(input=payload, timeout=2)
                break
            except subprocess.TimeoutExpired:
                payload = None
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.communicate()
                    raise GitError("timeout", " ".join(args[:2])) from None
                if network and _dir_bytes(self.gitdir / "objects") > self.config.max_bytes:
                    proc.kill()
                    proc.communicate()
                    raise GitError("too_large", f"object store over {self.config.max_bytes} bytes") from None
        if proc.returncode != 0:
            message = err.decode("utf-8", "replace").strip().splitlines()
            detail = (message[-1] if message else f"exit {proc.returncode}")[:200]
            lowered = detail.lower()
            status = "unavailable" if any(p in lowered for p in PERMANENT) else "transient"
            raise GitError(status, detail)
        if network and _dir_bytes(self.gitdir / "objects") > self.config.max_bytes:
            raise GitError("too_large", f"object store over {self.config.max_bytes} bytes")
        return out

    def init(self, url: str, *, partial: bool = True) -> None:
        """A bare repository; ``partial``: a blob:none promisor of ``url`` (else a plain object store)."""
        if (self.gitdir / "config").exists():
            return
        self.gitdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.run("init", "-q", "--bare")
        if not partial:
            self.run("config", "gc.auto", "0")
            return
        for key, value in (
            ("core.repositoryformatversion", "1"),
            ("extensions.partialclone", "origin"),
            ("remote.origin.url", url),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", "blob:none"),
            ("gc.auto", "0"),
        ):
            self.run("config", key, value)


def _retry(limiter: Limiter, config: FetchConfig, git: Git, *args: str) -> bytes:
    for attempt in range(config.retries + 1):
        limiter.wait()
        try:
            out = git.run(*args, network=True)
        except GitError as exc:
            if exc.status not in {"transient", "timeout"} or attempt == config.retries:
                raise
            time.sleep(limiter.failed())
            continue
        limiter.succeeded()
        return out
    raise AssertionError("unreachable")


def raw_diff(git: Git, parent: str, sha: str) -> list[tuple[str, str, str, str]]:
    """(status, path, old blob, new blob) per changed file; renames off so no blob is needed."""
    out = git.run("diff-tree", "-r", "--no-renames", "--raw", "--no-abbrev", "-z", parent, sha)
    fields = out.decode("utf-8", "replace").split("\0")
    entries = []
    i = 0
    while i + 1 < len(fields):
        meta, path = fields[i], fields[i + 1]
        i += 2
        parts = meta.lstrip(":").split()
        if len(parts) < 5:
            continue
        old_mode, new_mode, old, new, status = parts[:5]
        if "160000" in (old_mode, new_mode):  # submodule
            continue
        entries.append((status[0], path, old, new))
    return entries


def tree_files(git: Git, commit: str) -> list[tuple[str, str]]:
    """(path, blob) of every regular file in ``commit`` (trees are local; no blob is fetched)."""
    out = git.run("ls-tree", "-r", "-z", "--full-tree", commit)
    rows = []
    for entry in out.decode("utf-8", "replace").split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob" and parts[0] in {"100644", "100755"}:
            rows.append((path, parts[2]))
    return rows


def read_blobs(git: Git, oids: list[str]) -> dict[str, str | None]:
    """Text of each blob (None for binary or oversized blobs)."""
    if not oids:
        return {}
    out = git.run("cat-file", "--batch", stdin="".join(o + "\n" for o in oids).encode())
    texts: dict[str, str | None] = {}
    pos = 0
    for oid in oids:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode().split()
        pos = nl + 1
        if len(header) < 3 or header[1] != "blob":  # "<oid> missing": never lazily fetched here
            texts[oid] = None
            continue
        size = int(header[2])
        data = out[pos : pos + size]
        pos += size + 1
        texts[oid] = None if size > MAX_BLOB_BYTES or b"\0" in data else data.decode("utf-8", "replace")
    return texts


ZERO = "0" * 40


def fetch_commit(
    git: Git, blobs: Git, *, limiter: Limiter, config: FetchConfig, repo: str, sha: str, url: str
) -> dict[str, Any]:
    """Commit and trees into the partial ``git``; the needed blobs into the plain ``blobs`` store.

    The blobs go to a separate repository with no commits: fetched into the shallow one, the server
    may leave out blobs reachable from the commit the client already has, and git then fetches them
    one by one (git 2.19 on the transfer node fails there with "shallow file has changed").
    """
    _retry(limiter, config, git, "fetch", "-q", "--no-tags", "--filter=blob:none", "--depth=2", "origin", sha)
    try:
        parent = git.run("rev-parse", "--verify", "-q", f"{sha}^1").decode().strip()
    except GitError:
        raise GitError("root_commit", "no parent") from None
    changed, excluded, other_code = [], [], []
    for status, path, old, new in raw_diff(git, parent, sha):
        if language_of(path) is None:
            if is_other_code(path) and path_reason(path) is None:
                other_code.append(path)
            continue
        reason = path_reason(path)
        if reason:
            excluded.append({"path": path, "reason": reason})
            continue
        changed.append((status, path, None if old == ZERO else old, None if new == ZERO else new))
    cap_dropped = 0
    if config.max_changed_files is not None and len(changed) > config.max_changed_files:
        order = random.Random(f"kestrixcodebench-test2-files\x1f{sha}")  # noqa: S311 - sampling, not security
        picked = set(order.sample(range(len(changed)), config.max_changed_files))
        cap_dropped = len(changed) - len(picked)
        changed = [c for i, c in enumerate(changed) if i in picked]
    changed_paths = {p for _, p, _, _ in changed}
    candidates = sorted(
        (p, o) for p, o in tree_files(git, parent) if p not in changed_paths and language_of(p) and not path_reason(p)
    )
    rng = random.Random(f"kestrixvul-negatives-v1\x1f{sha}")  # noqa: S311 - sampling, not security
    sampled = rng.sample(candidates, min(config.sampled_files, len(candidates)))
    oids = sorted({o for _, _, a, b in changed for o in (a, b) if o} | {o for _, o in sampled})
    for i in range(0, len(oids), BLOB_CHUNK):
        _retry(limiter, config, blobs, "fetch", "-q", "--no-tags", url, *oids[i : i + BLOB_CHUNK])
    texts = read_blobs(blobs, oids)
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": repo,
        "sha": sha,
        "parent": parent,
        "fetched_at": now(),
        "files": [
            {
                "path": p,
                "status": s,
                "before": texts.get(a) if a else None,
                "after": texts.get(b) if b else None,
                "unreadable": bool((a and texts.get(a) is None) or (b and texts.get(b) is None)),
            }
            for s, p, a, b in changed
        ],
        "excluded": excluded,
        "cap_dropped": cap_dropped,
        "other_code_changed": sorted(other_code),
        "sampled": [{"path": p, "text": texts.get(o)} for p, o in sampled if texts.get(o) is not None],
    }


class Status:
    """Append-only ``mine/status.jsonl``; the last line per commit wins."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.last: dict[str, dict[str, Any]] = {r["sha"]: r for r in read_jsonl(path)}

    def record(self, repo: str, sha: str, status: str, detail: str = "") -> None:
        row = {"repo": repo, "sha": sha, "status": status, "detail": detail[:200], "at": now()}
        with self.lock:
            self.last[sha] = row
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    def final(self, sha: str) -> bool:
        """True when the commit needs no retry (fetched, or failed permanently)."""
        row = self.last.get(sha)
        return row is not None and row["status"] not in {"transient", "timeout"}


def commit_path(mine: Path, sha: str) -> Path:
    return mine / "commits" / f"{sha}.json.gz"


def mine_repo(
    mine: Path, repo: str, shas: list[str], *, limiter: Limiter, config: FetchConfig, status: Status
) -> Counter[str]:
    counts: Counter[str] = Counter()
    todo = [s for s in shas if not commit_path(mine, s).exists() and not status.final(s)]
    if not todo:
        counts["skipped_done"] += len(shas)
        return counts
    gitdir = mine / "repos" / (repo.replace("/", "__") + ".git")
    git = Git(gitdir, mine / "home", config)
    blobs = Git(gitdir / "blobs.git", mine / "home", config)
    try:
        url = remote_url(repo)
        git.init(url)
        blobs.init(url, partial=False)
        for sha in todo:
            try:
                record = fetch_commit(git, blobs, limiter=limiter, config=config, repo=repo, sha=sha, url=url)
            except GitError as exc:
                status.record(repo, sha, exc.status, exc.detail)
                counts[f"failed:{exc.status}"] += 1
                if exc.status == "too_large" or any(p in exc.detail.lower() for p in REPO_FATAL):
                    for rest in todo[todo.index(sha) + 1 :]:
                        status.record(repo, rest, exc.status, "same repository")
                        counts[f"failed:{exc.status}"] += 1
                    break
                continue
            out = commit_path(mine, sha)
            out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = out.with_name(out.name + ".tmp")
            with gzip.open(tmp, "wt", encoding="utf-8") as fh:
                json.dump(record, fh, sort_keys=True)
            tmp.chmod(0o600)
            tmp.replace(out)
            status.record(repo, sha, "fetched")
            counts["fetched"] += 1
    except GitError as exc:
        for sha in todo:
            status.record(repo, sha, exc.status, exc.detail)
        counts[f"failed:{exc.status}"] += len(todo)
    finally:
        shutil.rmtree(gitdir, ignore_errors=True)
    return counts


def fetch(
    root: Path, *, workers: int = 8, interval: float = 1.0, config: FetchConfig | None = None, limit: int | None = None
) -> dict[str, Any]:
    config = config or FetchConfig()
    mine = root / "mine"
    for d in (mine, mine / "commits", mine / "repos", mine / "home"):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    by_repo: dict[str, list[str]] = defaultdict(list)
    for row in read_jsonl(root / "work" / "mine_targets.jsonl"):
        by_repo[row["repo"]].append(row["sha"])
    repos = sorted(by_repo)[:limit] if limit else sorted(by_repo)
    status = Status(mine / "status.jsonl")
    limiter = Limiter(interval)
    totals: Counter[str] = Counter()
    lock = threading.Lock()
    done = 0
    started = time.monotonic()

    def one(repo: str) -> None:
        nonlocal done
        counts = mine_repo(mine, repo, sorted(set(by_repo[repo])), limiter=limiter, config=config, status=status)
        with lock:
            totals.update(counts)
            done += 1
            if done % 50 == 0:
                rate = done / max(1.0, time.monotonic() - started)
                print(f"fetch: {done}/{len(repos)} repositories, {dict(totals)}, {rate:.2f} repos/s", flush=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, repos))
    return {
        "schema_version": SCHEMA_VERSION,
        "stage": "fetch",
        "repositories": len(repos),
        "counts": dict(sorted(totals.items())),
        "config": {
            "workers": workers,
            "interval_s": interval,
            "timeout_s": config.timeout,
            "max_bytes": config.max_bytes,
            "retries": config.retries,
            "sampled_files": config.sampled_files,
        },
    }


# --- stage 3: extract -----------------------------------------------------------------------


def _advisory_meta(root: Path) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in read_jsonl(root / "work" / "ghsa_text.jsonl")}


FENCED = re.compile(r"^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$", re.MULTILINE | re.DOTALL)
INDENTED = re.compile(r"^(?: {4,}|\t).*$", re.MULTILINE)
URL = re.compile(r"https?://\S+")


def prose(details: str) -> str:
    """Advisory details without fenced or indented code blocks and URLs.

    PrimeVul's NVDCheck reads the short NVD description. GHSA details often add proof-of-concept and
    patch code, which names many functions that are not the vulnerable one; inline mentions such as
    "the `render` function" stay.
    """
    return URL.sub(" ", INDENTED.sub("", FENCED.sub("", details)))


def descriptions(advisories: list[dict[str, Any]]) -> list[str]:
    """NVDCheck texts: the advisory summary, its details as prose, and the linked CVE descriptions."""
    out: list[str] = []
    for adv in advisories:
        out += [t for t in (adv["summary"], prose(adv["details"]), *adv["cve_descriptions"]) if t.strip()]
    return out


def code_sha256(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


@dataclass
class Units:
    files: list[FileUnits]
    other: int  # changed functions OneFunc counts outside these files (other languages, shadow units)
    negatives: list[tuple[str, str, Func, str]]  # (path, language, unchanged function, origin)


def commit_units(record: dict[str, Any], stats: Counter[str]) -> Units:
    """Changed functions per kept file, plus the unchanged functions available as negatives."""
    units = Units([], len(record["other_code_changed"]), [])
    for f in record["files"]:
        language = language_of(f["path"]) or ""
        stats[f"files:{language}"] += 1
        reason = (
            content_reason(f["before"]) or content_reason(f["after"]) or ("unreadable" if f["unreadable"] else None)
        )
        before = functions(f["before"], language, f["path"]) if f["before"] and not reason else []
        after = functions(f["after"], language, f["path"]) if f["after"] and not reason else []
        if not reason and (before is None or after is None):
            reason = "too_complex"
            units.other += 1  # its changes are unknown, so OneFunc must not fire
        if reason or before is None or after is None:
            stats[f"file_excluded:{reason}"] += 1
            units.files.append(FileUnits(f["path"], language, reason, []))
            continue
        diff = diff_functions(before, after)
        units.other += diff.shadow_changed
        units.files.append(FileUnits(f["path"], language, None, diff.changes))
        units.negatives += [(f["path"], language, fn, "changed_file") for fn in diff.unchanged]
    for s in record["sampled"]:
        language = language_of(s["path"]) or ""
        funcs = None if content_reason(s["text"]) else functions(s["text"], language, s["path"])
        units.negatives += [(s["path"], language, fn, "parent_snapshot") for fn in funcs or [] if not fn.shadow]
    return units


def _commit_fields(record: dict[str, Any], target: dict[str, Any], advs: list[dict[str, Any]]) -> dict[str, Any]:
    ids: set[str] = set(target["advisories"])
    for adv in advs:
        ids |= set(adv["aliases"])
    dates = [a["published"] for a in advs if a.get("published")] or (
        [target["published"]] if target.get("published") else []
    )
    repo = repo_key(f"github.com/{record['repo']}")
    return {
        "repo": repo,
        "repos": [repo],
        "commit": record["sha"],
        "cve_ids": sorted(c for c in ids if c.startswith("CVE-")),
        "advisory_ids": sorted(ids),
        "published": min(dates)[:10] if dates else None,
    }


def extract_commit(
    record: dict[str, Any], target: dict[str, Any], meta: dict[str, dict[str, Any]], stats: Counter[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(vulnerable candidates, negative candidates) of one fetched commit."""
    sha = record["sha"]
    advs = [meta[a] for a in target["advisories"] if a in meta]
    units = commit_units(record, stats)
    common = _commit_fields(record, target, advs)
    stats["commits"] += 1
    candidates: list[dict[str, Any]] = []
    cwes = sorted({c for a in advs for c in a["cwes"]})
    labelled = label_commit(units.files, units.other, descriptions(advs)) if target["role"] == "ghsa" else iter(())
    for fu, change, label in labelled:
        key = f"ghsa/{fu.language}"
        stats[f"{key}:functions_changed:{change.kind}"] += 1
        stats[f"{key}:label:{label}"] += 1
        if label == "uncertain":
            continue
        drop = f"no_before_version_{change.kind}" if change.before is None else size_reason(change.before)
        if drop or change.before is None:
            stats[f"{key}:vulnerable_dropped:{drop}"] += 1
            continue
        stats[f"{key}:vulnerable_kept"] += 1
        candidates.append(
            {
                "id": record_id("ghsa", sha, fu.path, change.name, change.before),
                "source": "ghsa",
                **common,
                "cwes": cwes,
                "language": fu.language,
                "path": fu.path,
                "function": change.name,
                "label_rule": label,
                "pair_kind": change.kind,
                "vulnerable": change.before,
                "patched": change.after,
            }
        )
    negatives = []
    for path, language, fn, origin in units.negatives:
        if size_reason(fn.code):
            stats["negatives_dropped:size"] += 1
            continue
        stats[f"negative_candidates:{language}:{origin}"] += 1
        negatives.append(
            {
                "id": record_id("negative", sha, path, fn.name, fn.code),
                "label": "negative_unchanged",
                "commit_role": target["role"],
                **common,
                "language": language,
                "path": path,
                "function": fn.name,
                "origin": origin,
                "code": fn.code,
            }
        )
    return candidates, negatives


def extract(root: Path) -> dict[str, Any]:
    meta = _advisory_meta(root)
    targets_by_sha = {r["sha"]: r for r in read_jsonl(root / "work" / "mine_targets.jsonl")}
    pool_meta: dict[str, str] = {}
    for record in read_jsonl(root / "work" / "split.jsonl"):
        if record.get("published"):
            sha = str(record["commit"]).lower()
            pool_meta[sha] = min(pool_meta.get(sha, "9999"), record["published"])
    stats: Counter[str] = Counter()
    status = Status(root / "mine" / "status.jsonl")
    stats.update(f"fetch_status:{r['status']}" for r in status.last.values())
    cand_out = root / "work" / "ghsa_candidates.jsonl"
    neg_out = root / "work" / "negative_candidates.jsonl"
    tmp_c, tmp_n = cand_out.with_name(cand_out.name + ".tmp"), neg_out.with_name(neg_out.name + ".tmp")
    with tmp_c.open("w", encoding="utf-8") as fc, tmp_n.open("w", encoding="utf-8") as fn:
        for path in sorted((root / "mine" / "commits").glob("*.json.gz")):
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                record = json.load(fh)
            target = dict(targets_by_sha.get(record["sha"]) or {})
            if not target:
                stats["commit_without_target"] += 1
                continue
            target["published"] = pool_meta.get(record["sha"])
            try:
                candidates, negatives = extract_commit(record, target, meta, stats)
            except (RecursionError, ValueError) as exc:  # a pathological file: skip the commit, count it
                stats[f"commit_failed:{type(exc).__name__}"] += 1
                continue
            fc.writelines(json.dumps(c, sort_keys=True) + "\n" for c in candidates)
            fn.writelines(json.dumps(n, sort_keys=True) + "\n" for n in negatives)
    for tmp, out in ((tmp_c, cand_out), (tmp_n, neg_out)):
        tmp.chmod(0o600)
        tmp.replace(out)
    return {"schema_version": SCHEMA_VERSION, "stage": "extract", "counts": dict(sorted(stats.items()))}
