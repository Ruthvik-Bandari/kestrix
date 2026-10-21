# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Download the corpora (transfer node only) and write the dataset manifest.

Standard library only, so it runs on the cluster transfer node without the project environment.
Each file is downloaded to ``*.part`` and renamed once complete; its size and SHA-256 are recorded on
the first download. A file already present is re-hashed and must match the manifest. A mismatch moves
it aside as ``*.rejected`` and fails the run. Files are 0600 in 0700 directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from .common import Layout, MailBenchError, file_sha256, now, private_dir, write_json, write_private
from .sources import SOURCES, Document, Source, SourceFile

CHUNK = 1 << 20
TIMEOUT_S = 120
RETRIES = 4
USER_AGENT = "kestrixmailbench-acquire/1 (research; contact via repository)"


class Response(Protocol):
    status: int
    headers: Any

    def read(self, n: int = -1, /) -> bytes: ...

    def close(self) -> None: ...


Opener = Callable[[urllib.request.Request], Response]


def _open(request: urllib.request.Request) -> Response:
    response: Response = urllib.request.urlopen(request, timeout=TIMEOUT_S)  # noqa: S310 - pinned https URLs only
    return response


def download(url: str, dest: Path, opener: Opener = _open, retries: int = RETRIES) -> dict[str, Any]:
    """Fetch ``url`` into ``dest``; return size, sha256 and the Last-Modified header."""
    if not url.startswith("https://"):
        raise MailBenchError(f"refusing non-https URL for {dest.name}")
    part = dest.with_name(dest.name + ".part")
    private_dir(dest.parent)
    for attempt in range(retries + 1):
        digest = hashlib.sha256()
        size = 0
        try:
            response = opener(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}))  # noqa: S310
            expected = response.headers.get("Content-Length")
            modified = response.headers.get("Last-Modified")
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                while chunk := response.read(CHUNK):
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            response.close()
            if expected is not None and int(expected) != size:
                raise OSError(f"short read: {size} of {expected} bytes")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if attempt == retries:
                raise MailBenchError(f"{dest.name}: download failed: {exc}") from exc
            time.sleep(min(30, 2**attempt))
            continue
        os.replace(part, dest)
        return {"size": size, "sha256": digest.hexdigest(), "last_modified": modified}
    raise MailBenchError(f"{dest.name}: download failed")  # pragma: no cover


def fetch_source(
    source: Source, layout: Layout, previous: dict[str, Any] | None = None, opener: Opener = _open
) -> dict[str, Any]:
    """Download or re-verify every file of ``source`` and return its manifest."""
    known = {f["filename"]: f for f in (previous or {}).get("files", [])}
    folder = layout.raw / source.name
    private_dir(folder)
    files: list[dict[str, Any]] = []
    entries: list[SourceFile | Document] = [*source.files, *source.documents]
    for entry in entries:
        dest = folder / entry.name
        record = known.get(entry.name)
        if dest.exists():
            sha = file_sha256(dest)
            if record is not None and record["sha256"] != sha:
                os.replace(dest, dest.with_name(dest.name + ".rejected"))
                raise MailBenchError(f"{entry.name}: sha256 {sha} does not match the manifest {record['sha256']}")
            record = record or {"url": entry.url, "last_modified": None, "downloaded_at": now()}
            record = {**record, "size": dest.stat().st_size, "sha256": sha}
        else:
            info = download(entry.url, dest, opener)
            record = {"url": entry.url, "downloaded_at": now(), **info}
        os.chmod(dest, 0o600)
        files.append(
            {
                "filename": entry.name,
                "url": entry.url,
                "kind": entry.kind if isinstance(entry, SourceFile) else "document",
                **record,
            }
        )
    return {
        "schema_version": 1,
        "source": source.name,
        "title": source.title,
        "landing_url": source.landing_url,
        "license": {"spdx": source.license_spdx, "note": source.license_note, "attribution": source.attribution},
        "capture_method": "https download, size and SHA-256 recorded on first download (trust on first use)",
        "files": files,
    }


def sha256sums(manifests: list[dict[str, Any]]) -> str:
    """``sha256sum -c`` compatible lines, paths relative to the raw directory."""
    lines = [f"{f['sha256']}  {m['source']}/{f['filename']}" for m in manifests for f in m["files"]]
    return "".join(line + "\n" for line in sorted(lines, key=lambda s: s.split("  ", 1)[1]))


def acquire(layout: Layout, names: list[str] | None = None, opener: Opener = _open) -> dict[str, Any]:
    """Fetch the named sources (all by default) and write ``manifests/``; return the combined manifest."""
    os.umask(0o077)
    wanted = set(names or [s.name for s in SOURCES])
    out: list[dict[str, Any]] = []
    for source in SOURCES:
        if source.name not in wanted:
            continue
        path = layout.manifests / f"{source.name}.json"
        previous = json.loads(path.read_text()) if path.exists() else None
        manifest = fetch_source(source, layout, previous, opener)
        write_json(path, manifest)
        out.append(manifest)
    combined = {"schema_version": 1, "generated_at": now(), "sources": out}
    write_json(layout.manifests / "mailbench-manifest.json", combined)
    write_private(layout.manifests / "SHA256SUMS", sha256sums(out).encode())
    return combined
