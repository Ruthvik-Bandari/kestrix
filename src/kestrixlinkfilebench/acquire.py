# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Download the datasets (transfer node only) and write the dataset manifest; standard library only.

The download, verification and manifest logic is ``kestrixmailbench.acquire`` (size and SHA-256 recorded on
the first download, a changed file rejected, files 0600 in 0700 directories); this module supplies the sources.
"""

from __future__ import annotations

import json
import os
from typing import Any

from kestrixmailbench.acquire import Opener, _open, fetch_source, sha256sums

from .common import Layout, now, write_json, write_private
from .sources import SOURCES


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
    write_json(layout.manifests / "linkfilebench-manifest.json", combined)
    write_private(layout.manifests / "SHA256SUMS", sha256sums(out).encode())
    return combined
