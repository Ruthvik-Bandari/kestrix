# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The local OSV vulnerability index: ``kestrix-scan db update`` and the lookups the scanner makes.

``update`` is the only code in kestrix-scan that uses the network. It downloads the OSV bulk export
for each ecosystem (``https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip``,
documented at https://google.github.io/osv.dev/data/) over HTTPS only, refuses redirects away from
HTTPS and anything over ``MAX_DOWNLOAD_BYTES``, and keeps the zip in the cache directory next to
an ``ETag`` so an unchanged export is not downloaded again. It then rebuilds ``osv.sqlite3`` from
every cached zip into a temporary file and renames it into place, so a reader never sees a
half-written index. The OSV exports include the OpenSSF malicious-packages feed (``MAL-`` ids).

The index holds, per advisory: id, aliases, summary, severity (``low`` to ``critical``, from the
CVSS v3 base score, else the GitHub ``database_specific.severity`` label, else ``medium``), CWE ids
and whether it is a malicious-package report; and per affected package: ecosystem, normalized
name, the OSV ``ranges`` and ``versions``. Lookups open the index read-only.

Cache directory: ``$KESTRIX_SCAN_DB`` when set, else ``%LOCALAPPDATA%\\kestrix-scan`` on Windows,
``~/Library/Caches/kestrix-scan`` on macOS and ``$XDG_CACHE_HOME/kestrix-scan`` (default
``~/.cache/kestrix-scan``) elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from .errors import Reason, Rejected
from .lockfiles import normalize
from .models import Severity

ECOSYSTEMS = ("PyPI", "npm")
OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"
DB_NAME = "osv.sqlite3"
SCHEMA_VERSION = "1"
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRY_BYTES = 16 * 1024 * 1024  # one advisory JSON file inside the zip
MAX_UNPACKED_BYTES = 8 * 1024 * 1024 * 1024  # the whole zip, uncompressed
STALE_AFTER_S = 7 * 24 * 3600
DOWNLOAD_TIMEOUT_S = 60
_CHUNK = 1024 * 1024
_GHSA_SEVERITY: dict[str, Severity] = {"LOW": "low", "MODERATE": "medium", "HIGH": "high", "CRITICAL": "critical"}

Progress = Callable[[str], None]


def cache_dir() -> Path:
    override = os.environ.get("KESTRIX_SCAN_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        return (Path(local) if local else Path.home() / "AppData" / "Local") / "kestrix-scan"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "kestrix-scan"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache") / "kestrix-scan"


def db_path() -> Path:
    return cache_dir() / DB_NAME


# ----- severity


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest number with one decimal place that is at least ``value``."""
    scaled = round(value * 100_000)
    return scaled / 100_000.0 if scaled % 10_000 == 0 else (math.floor(scaled / 10_000) + 1) / 10.0


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_score(vector: str) -> float | None:
    """The CVSS v3.0/v3.1 base score of a vector string, or None when it is not a complete v3 base vector."""
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[metrics["UI"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploitability), 10.0) if changed else min(impact + exploitability, 10.0))


def score_severity(score: float) -> Severity:
    """CVSS qualitative rating: 9.0 and up critical, 7.0 high, 4.0 medium, below that low."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def advisory_severity(record: dict[str, Any]) -> Severity:
    scores = [
        score
        for item in record.get("severity") or []
        if isinstance(item, dict) and isinstance(item.get("score"), str)
        for score in [cvss3_score(item["score"])]
        if score is not None
    ]
    if scores:
        return score_severity(max(scores))
    specific = record.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None
    return _GHSA_SEVERITY.get(label.upper(), "medium") if isinstance(label, str) else "medium"


def advisory_cwes(record: dict[str, Any]) -> list[str]:
    specific = record.get("database_specific")
    ids = specific.get("cwe_ids") if isinstance(specific, dict) else None
    return [item for item in ids if isinstance(item, str) and item.startswith("CWE-")] if isinstance(ids, list) else []


# ----- index


_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE sources (
    ecosystem TEXT PRIMARY KEY, url TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
    downloaded_at TEXT NOT NULL, etag TEXT, advisories INTEGER NOT NULL, malicious INTEGER NOT NULL
);
CREATE TABLE advisories (
    id TEXT PRIMARY KEY, aliases TEXT NOT NULL, summary TEXT NOT NULL, severity TEXT NOT NULL,
    cwes TEXT NOT NULL, malicious INTEGER NOT NULL
);
CREATE TABLE affected (advisory TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, ranges TEXT NOT NULL, versions TEXT NOT NULL);
CREATE INDEX affected_package ON affected (ecosystem, name);
"""


@dataclass(frozen=True, slots=True)
class Source:
    """One downloaded export: where it came from, its SHA-256, size, download time (UTC ISO 8601) and ETag."""

    ecosystem: str
    url: str
    sha256: str
    size: int
    downloaded_at: str
    etag: str | None = None


def _records(archive: Path) -> Iterator[dict[str, Any]]:
    """Each advisory JSON in an OSV zip, with size limits against oversized or compressed-bomb entries."""
    with zipfile.ZipFile(archive) as bundle:
        entries = [info for info in bundle.infolist() if info.filename.endswith(".json") and not info.is_dir()]
        if sum(info.file_size for info in entries) > MAX_UNPACKED_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"{archive} unpacks to more than {MAX_UNPACKED_BYTES:,} bytes")
        for info in entries:
            if info.file_size > MAX_ENTRY_BYTES:
                continue
            with bundle.open(info) as stream:
                data = stream.read(MAX_ENTRY_BYTES + 1)
            if len(data) > MAX_ENTRY_BYTES:
                continue
            try:
                record = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if isinstance(record, dict) and isinstance(record.get("id"), str):
                yield record


def _index_records(db: sqlite3.Connection, ecosystem: str, records: Iterable[dict[str, Any]]) -> tuple[int, int]:
    advisories = malicious = 0
    for record in records:
        if record.get("withdrawn"):
            continue
        rows = []
        for item in record.get("affected") or []:
            package = item.get("package") if isinstance(item, dict) else None
            if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
                continue
            name = package.get("name")
            if not isinstance(name, str) or not name:
                continue
            ranges = [r for r in item.get("ranges") or [] if isinstance(r, dict) and r.get("type") != "GIT"]
            versions = [v for v in item.get("versions") or [] if isinstance(v, str)]
            rows.append((record["id"], ecosystem, normalize(ecosystem, name), json.dumps(ranges), json.dumps(versions)))
        if not rows:
            continue
        aliases = [a for a in record.get("aliases") or [] if isinstance(a, str)]
        summary = record.get("summary") or record.get("details") or ""
        is_malicious = record["id"].startswith("MAL-")
        inserted = db.execute(
            "INSERT OR IGNORE INTO advisories VALUES (?, ?, ?, ?, ?, ?)",
            (
                record["id"],
                json.dumps(aliases),
                str(summary).strip().splitlines()[0][:300] if str(summary).strip() else "",
                advisory_severity(record),
                json.dumps(advisory_cwes(record)),
                int(is_malicious),
            ),
        ).rowcount
        if not inserted:
            continue
        db.executemany("INSERT INTO affected VALUES (?, ?, ?, ?, ?)", rows)
        advisories += 1
        malicious += int(is_malicious)
    return advisories, malicious


def build_index(sources: dict[str, tuple[Path, Source]], target: Path, progress: Progress | None = None) -> None:
    """Build the index from the cached exports into a temporary file, then rename it over ``target``."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".osv-", suffix=".sqlite3")
    os.close(fd)
    try:
        db = sqlite3.connect(tmp)
        try:
            db.executescript(_SCHEMA)
            for ecosystem, (archive, source) in sorted(sources.items()):
                if progress is not None:
                    progress(f"{ecosystem}: indexing {archive.name}")
                count, malicious = _index_records(db, ecosystem, _records(archive))
                db.execute(
                    "INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        ecosystem,
                        source.url,
                        source.sha256,
                        source.size,
                        source.downloaded_at,
                        source.etag,
                        count,
                        malicious,
                    ),
                )
            db.executemany(
                "INSERT INTO meta VALUES (?, ?)",
                [("schema", SCHEMA_VERSION), ("built_at", _now())],
            )
            db.commit()
        finally:
            db.close()
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ----- download


def _opener() -> Any:
    import urllib.request

    class HttpsOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:  # noqa: PLR0917 - urllib's signature
            if not newurl.startswith("https://"):
                raise Rejected(Reason.INVALID_INPUT, f"refused a redirect away from HTTPS: {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return urllib.request.build_opener(HttpsOnly)


def _copy(
    response: IO[bytes], out: IO[bytes], total: int | None, label: str, progress: Progress | None
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    shown = 0.0
    while chunk := response.read(_CHUNK):
        size += len(chunk)
        if size > MAX_DOWNLOAD_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"{label}: download is larger than {MAX_DOWNLOAD_BYTES:,} bytes")
        digest.update(chunk)
        out.write(chunk)
        if progress is not None and time.monotonic() - shown >= 0.5:
            shown = time.monotonic()
            of = f" of {total / 1e6:.1f} MB" if total else ""
            progress(f"{label}: {size / 1e6:.1f} MB{of}")
    return digest.hexdigest(), size


def download(ecosystem: str, directory: Path, previous: Source | None, progress: Progress | None = None) -> Source:
    """Download one ecosystem's export to ``directory/<ecosystem>.zip`` (atomically); reuse it on HTTP 304."""
    import urllib.error
    import urllib.request

    url = OSV_URL.format(ecosystem=ecosystem)
    if not url.startswith("https://"):
        raise Rejected(Reason.INVALID_INPUT, f"refusing a non-HTTPS URL: {url}")
    archive = directory / f"{ecosystem}.zip"
    request = urllib.request.Request(url, headers={"User-Agent": "kestrix-scan (offline OSV index)"})  # noqa: S310 - fixed https URL
    if previous is not None and previous.etag and archive.is_file():
        request.add_header("If-None-Match", previous.etag)
    try:
        response = _opener().open(request, timeout=DOWNLOAD_TIMEOUT_S)
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and previous is not None:
            if progress is not None:
                progress(f"{ecosystem}: unchanged since {previous.downloaded_at}")
            return Source(ecosystem, url, previous.sha256, previous.size, _now(), previous.etag)
        raise Rejected(Reason.INVALID_INPUT, f"{url}: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise Rejected(Reason.INVALID_INPUT, f"{url}: {getattr(exc, 'reason', exc)}") from None
    with response:
        if not response.geturl().startswith("https://"):
            raise Rejected(Reason.INVALID_INPUT, f"refused a non-HTTPS response from {response.geturl()}")
        length = response.headers.get("Content-Length")
        total = int(length) if length and length.isdigit() else None
        if total is not None and total > MAX_DOWNLOAD_BYTES:
            raise Rejected(
                Reason.INPUT_TOO_LARGE, f"{url} is {total:,} bytes, over the {MAX_DOWNLOAD_BYTES:,} byte cap"
            )
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{ecosystem}-", suffix=".zip")
        try:
            with os.fdopen(fd, "wb") as out:
                sha256, size = _copy(response, out, total, ecosystem, progress)
            if total is not None and size != total:
                raise Rejected(Reason.INVALID_INPUT, f"{url}: got {size:,} of {total:,} bytes")
            if not zipfile.is_zipfile(tmp):
                raise Rejected(Reason.INVALID_INPUT, f"{url} did not return a zip file")
            os.replace(tmp, archive)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        etag = response.headers.get("ETag")
    return Source(ecosystem, url, sha256, size, _now(), etag)


def update(ecosystems: Iterable[str], *, progress: Progress | None = None) -> Path:
    """Download the given ecosystems' exports and rebuild the index from every cached export. Returns the index path."""
    wanted = list(dict.fromkeys(ecosystems))
    unknown = [e for e in wanted if e not in ECOSYSTEMS]
    if unknown:
        raise Rejected(
            Reason.INVALID_INPUT, f"unsupported ecosystem {unknown[0]!r}; choose from {', '.join(ECOSYSTEMS)}"
        )
    directory = cache_dir()
    downloads = directory / "downloads"
    known = {s.ecosystem: s for s in sources()}
    found: dict[str, tuple[Path, Source]] = {}
    for ecosystem in wanted:
        found[ecosystem] = (
            downloads / f"{ecosystem}.zip",
            download(ecosystem, downloads, known.get(ecosystem), progress),
        )
    for ecosystem, source in known.items():  # keep ecosystems downloaded earlier and still cached
        archive = downloads / f"{ecosystem}.zip"
        if ecosystem not in found and archive.is_file():
            found[ecosystem] = (archive, source)
    build_index(found, db_path(), progress)
    return db_path()


# ----- lookups


def connect(path: Path | None = None) -> sqlite3.Connection | None:
    """A read-only connection to the index, or None when there is none or it cannot be read."""
    target = path or db_path()
    if not target.is_file():
        return None
    try:
        db = sqlite3.connect(f"{target.resolve().as_uri()}?mode=ro", uri=True)
        if db.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone() != (SCHEMA_VERSION,):
            db.close()
            return None
    except sqlite3.Error:
        return None
    return db


def sources(db: sqlite3.Connection | None = None) -> list[Source]:
    """The exports the index was built from; empty when there is no index."""
    own = db is None
    db = db or connect()
    if db is None:
        return []
    try:
        rows = db.execute(
            "SELECT ecosystem, url, sha256, bytes, downloaded_at, etag FROM sources ORDER BY ecosystem"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        if own:
            db.close()
    return [Source(*row) for row in rows]


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: Severity
    cwes: tuple[str, ...]
    malicious: bool
    ranges: list[Any]
    versions: list[str]


def advisories_for(db: sqlite3.Connection, ecosystem: str, name: str) -> list[Advisory]:
    """Every advisory naming this package, whatever the version."""
    rows = db.execute(
        "SELECT a.id, a.aliases, a.summary, a.severity, a.cwes, a.malicious, f.ranges, f.versions "
        "FROM affected f JOIN advisories a ON a.id = f.advisory WHERE f.ecosystem = ? AND f.name = ? ORDER BY a.id",
        (ecosystem, normalize(ecosystem, name)),
    ).fetchall()
    return [
        Advisory(
            row[0],
            tuple(json.loads(row[1])),
            row[2],
            row[3],
            tuple(json.loads(row[4])),
            bool(row[5]),
            json.loads(row[6]),
            json.loads(row[7]),
        )
        for row in rows
    ]


@dataclass(frozen=True, slots=True)
class Status:
    path: Path
    built_at: str | None
    sources: list[Source]
    counts: dict[str, tuple[int, int]]  # ecosystem -> (advisories, malicious)

    def age_s(self, now: float | None = None) -> float | None:
        """Seconds since the oldest export was downloaded, or None without an index."""
        if not self.sources:
            return None
        oldest = min(datetime.fromisoformat(s.downloaded_at).timestamp() for s in self.sources)
        return (now if now is not None else time.time()) - oldest


def status(path: Path | None = None) -> Status:
    target = path or db_path()
    db = connect(target)
    if db is None:
        return Status(target, None, [], {})
    try:
        built = db.execute("SELECT value FROM meta WHERE key = 'built_at'").fetchone()
        counts = {
            row[0]: (row[1], row[2]) for row in db.execute("SELECT ecosystem, advisories, malicious FROM sources")
        }
        return Status(target, built[0] if built else None, sources(db), counts)
    finally:
        db.close()
