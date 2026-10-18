"""Content-addressed evidence store and run provenance (plan section 7)."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .. import ATTRIBUTION, __version__


def canonical_json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_artifact(root: Path, obj: object) -> tuple[str, Path]:
    """Write to a temp file, hash, then atomically rename to ``<sha256>.json``."""
    data = canonical_json(obj)
    digest = hashlib.sha256(data).hexdigest()
    root.mkdir(parents=True, exist_ok=True)
    final = root / f"{digest}.json"
    if not final.exists():
        fd, tmp = tempfile.mkstemp(dir=root, prefix=".tmp-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, final)
    return digest, final


def _git_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - resolved from PATH like any developer tool
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
            cwd=Path(__file__).parent,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def run_manifest(started: str, **extra: object) -> dict[str, object]:
    return {
        "generated_by": ATTRIBUTION,
        "kestrix_version": __version__,
        "git_sha": _git_sha(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "started_at": started,
        "finished_at": now(),
        **extra,
    }
