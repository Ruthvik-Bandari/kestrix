"""Fetch each pinned source at its exact commit and record a license and content manifest.

Uses a shallow fetch of the pinned commit plus a sparse checkout, so only the directories the
benchmark needs are materialized. The sparse patterns are written as a classic
``info/sparse-checkout`` file, equivalent to cone mode, so git 2.19 (the cluster transfer
node) works without the newer ``git sparse-checkout`` command. The checkout must resolve to the pinned commit or the
acquisition fails; nothing is silently taken from a moving branch.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from kestrix.core.evidence import now

from .sources import Source

GIT_TIMEOUT_S = 1800


class AcquisitionError(RuntimeError):
    pass


def _git(cwd: Path, *args: str) -> str:
    try:
        out = subprocess.run(  # noqa: S603 - argument list, no shell
            ["git", *args],  # noqa: S607 - git from PATH, arguments are fixed or pinned values
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise AcquisitionError(f"git {args[0]} failed: {exc.stderr.strip()[-500:]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"git {args[0]} timed out after {GIT_TIMEOUT_S}s") from exc
    return out.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _head(dest: Path) -> str | None:
    if not (dest / ".git").is_dir():
        return None
    try:
        return _git(dest, "rev-parse", "HEAD")
    except AcquisitionError:
        return None


def sparse_patterns(paths: tuple[str, ...]) -> list[str]:
    """Cone-mode patterns: root files, each parent directory's files, and the full listed directories."""
    full = sorted({p.strip("/") for p in paths})
    full = [p for p in full if not any(p != q and p.startswith(q + "/") for q in full)]
    lines = ["/*", "!/*/"]
    seen: set[str] = set()
    for path in full:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            parent = "/".join(parts[:depth])
            if parent not in seen and parent not in full:
                seen.add(parent)
                lines += [f"/{parent}/", f"!/{parent}/*/"]
        lines.append(f"/{path}/")
    return lines


def checkout(source: Source, dest: Path) -> None:
    """Materialize ``source`` at its pinned commit in ``dest``; reuse a matching checkout."""
    if _head(dest) == source.commit:
        return
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    _git(dest, "init", "--quiet")
    _git(dest, "remote", "add", "origin", source.url)
    _git(dest, "config", "core.sparseCheckout", "true")
    (dest / ".git" / "info").mkdir(exist_ok=True)
    (dest / ".git" / "info" / "sparse-checkout").write_text("\n".join(sparse_patterns(source.paths)) + "\n")
    _git(dest, "-c", "protocol.version=2", "fetch", "--quiet", "--depth", "1", "origin", source.commit)
    _git(dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD")
    head = _head(dest)
    if head != source.commit:
        raise AcquisitionError(f"{source.name}: checked out {head}, expected pinned {source.commit}")


def manifest(source: Source, dest: Path) -> dict[str, object]:
    """Per-file SHA-256 over the materialized paths plus the license record."""
    head = _head(dest)
    if head != source.commit:
        raise AcquisitionError(f"{source.name}: checkout at {head}, expected pinned {source.commit}")
    license_path = dest / source.license_file
    if not license_path.is_file():
        raise AcquisitionError(f"{source.name}: license file {source.license_file} is missing")
    files: dict[str, str] = {}
    for rel in source.paths:
        root = dest / rel
        if not root.is_dir():
            raise AcquisitionError(f"{source.name}: pinned path {rel} is missing")
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            files[path.relative_to(dest).as_posix()] = sha256_file(path)
    content = hashlib.sha256("".join(f"{k}\0{v}\n" for k, v in files.items()).encode()).hexdigest()
    return {
        "schema_version": 1,
        "source": source.name,
        "url": source.url,
        "commit": source.commit,
        "revision_label": source.revision_label,
        "license": {
            "spdx": source.license_spdx,
            "file": source.license_file,
            "sha256": sha256_file(license_path),
            "allowed_use": source.allowed_use,
            "attribution": source.attribution,
        },
        "capture_method": "public repository, shallow sparse git fetch at pinned commit",
        "collected_at": now(),
        "paths": list(source.paths),
        "file_count": len(files),
        "total_bytes": sum((dest / k).stat().st_size for k in files),
        "content_sha256": content,
        "files": files,
    }
