# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Download the pinned archives with resume, verify size, MD5 and SHA-256, and write manifests.

Standard library only, so it runs on the cluster transfer node without the project environment.
A file is accepted only when its size and MD5 match the Zenodo record and, once pinned, its
SHA-256 matches too. A mismatch moves the file aside as ``*.rejected`` and fails the run; nothing
unverified is ever left under its final name. Git sources reuse the pinned sparse checkout from
``kestrixbench.acquire``.
"""

from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .sources import ArchiveSource, Artifact

CHUNK = 1 << 20
TIMEOUT_S = 120
RETRIES = 8
USER_AGENT = "kestrixvul-acquire/1 (research; contact via repository)"


class VerificationError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digests(path: Path) -> tuple[str, str]:
    """(md5, sha256) of a file in one pass."""
    md5 = hashlib.md5(
        usedforsecurity=False
    )  # kestrix: ignore[py.crypto.weak_hash] Zenodo publishes MD5 checksums; SHA-256 is verified too
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def verify(path: Path, artifact: Artifact) -> str:
    """Return the file's SHA-256 if it matches every recorded check; raise otherwise."""
    size = path.stat().st_size
    if size != artifact.size:
        raise VerificationError(f"{artifact.filename}: size {size}, expected {artifact.size}")
    md5, sha = digests(path)
    if md5 != artifact.md5:
        raise VerificationError(f"{artifact.filename}: md5 {md5}, expected {artifact.md5}")
    if artifact.sha256 is not None and sha != artifact.sha256:
        raise VerificationError(f"{artifact.filename}: sha256 {sha}, expected pinned {artifact.sha256}")
    return sha


class Response(Protocol):
    status: int

    def read(self, n: int = -1, /) -> bytes: ...

    def close(self) -> None: ...


Opener = Callable[[urllib.request.Request], Response]


def _open(request: urllib.request.Request) -> Response:
    response: Response = urllib.request.urlopen(request, timeout=TIMEOUT_S)  # noqa: S310 - pinned https URLs only
    return response


def download(artifact: Artifact, dest: Path, opener: Opener = _open, retries: int = RETRIES) -> None:
    """Fetch ``artifact`` into ``dest`` (a ``.part`` file grows until complete, then is renamed)."""
    if not artifact.url.startswith("https://"):
        raise VerificationError(f"{artifact.filename}: refusing non-https URL")
    part = dest.with_name(dest.name + ".part")
    for attempt in range(retries + 1):
        have = part.stat().st_size if part.exists() else 0
        if have > artifact.size:
            part.unlink()
            have = 0
        if have == artifact.size:
            break
        request = urllib.request.Request(artifact.url, headers={"User-Agent": USER_AGENT})  # noqa: S310
        if have:
            request.add_header("Range", f"bytes={have}-")
        try:
            response = opener(request)
            if have and response.status != 206:
                part.unlink()  # server ignored the range: restart from zero
                continue
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as out:
                while chunk := response.read(CHUNK):
                    out.write(chunk)
            response.close()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if attempt == retries:
                raise VerificationError(f"{artifact.filename}: download failed: {exc}") from exc
            time.sleep(min(60, 2**attempt))
    if not part.exists() or part.stat().st_size != artifact.size:
        raise VerificationError(f"{artifact.filename}: incomplete after {retries} retries")
    os.replace(part, dest)


def fetch(source: ArchiveSource, raw: Path, opener: Opener = _open) -> dict[str, object]:
    """Download (or reuse) and verify every artifact of ``source``; return its manifest."""
    folder = raw / source.name
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    files = []
    for artifact in source.artifacts:
        dest = folder / artifact.filename
        if not dest.exists():
            download(artifact, dest, opener)
        try:
            sha = verify(dest, artifact)
        except VerificationError:
            os.replace(dest, dest.with_name(dest.name + ".rejected"))
            raise
        os.chmod(dest, 0o600)
        files.append(
            {
                "filename": artifact.filename,
                "url": artifact.url,
                "size": artifact.size,
                "md5": artifact.md5,
                "sha256": sha,
                "sha256_pinned": artifact.sha256 is not None,
            }
        )
    return {
        "schema_version": 1,
        "source": source.name,
        "title": source.title,
        "revision_label": source.revision_label,
        "doi": source.doi,
        "record_url": source.record_url,
        "license": {"spdx": source.license_spdx, "allowed_use": source.allowed_use, "attribution": source.attribution},
        "capture_method": "Zenodo record download over https, resumable, verified against the record's size and md5",
        "collected_at": now(),
        "files": files,
    }


def sha256sums(manifests: list[dict[str, object]]) -> str:
    """``sha256sum -c`` compatible lines (paths relative to the raw directory)."""
    lines = []
    for record in manifests:
        files = record["files"]
        if isinstance(files, list):
            lines += [f"{f['sha256']}  {record['source']}/{f['filename']}" for f in files]
        elif isinstance(files, dict):
            lines += [f"{sha}  {record['source']}/{rel}" for rel, sha in files.items()]
    return "".join(line + "\n" for line in sorted(lines, key=lambda s: s.split("  ", 1)[1]))
