# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Synthetic OSV advisories, bulk-export zips built in the test, and an index built from them. Nothing is downloaded."""

import json
import zipfile
from pathlib import Path
from typing import Any

from kestrix_scan import osvdb

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
CVSS_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 5.4


def advisory(
    osv_id: str,
    ecosystem: str,
    name: str,
    *,
    events: list[dict[str, str]] | None = None,
    versions: list[str] | None = None,
    aliases: list[str] | None = None,
    summary: str = "",
    cvss: str | None = None,
    severity_label: str | None = None,
    cwes: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    affected: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
    if events is not None:
        affected["ranges"] = [{"type": "SEMVER" if ecosystem == "npm" else "ECOSYSTEM", "events": events}]
    if versions is not None:
        affected["versions"] = versions
    record: dict[str, Any] = {
        "schema_version": "1.6.0",
        "id": osv_id,
        "modified": "2026-10-01T00:00:00Z",
        "aliases": aliases or [],
        "summary": summary or f"Synthetic advisory {osv_id}",
        "affected": [affected],
        **extra,
    }
    if cvss is not None:
        record["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    specific: dict[str, Any] = {}
    if severity_label is not None:
        specific["severity"] = severity_label
    if cwes is not None:
        specific["cwe_ids"] = cwes
    if specific:
        record["database_specific"] = specific
    return record


PYPI = [
    advisory(
        "GHSA-aaaa-bbbb-cccc",
        "PyPI",
        "Demo_Pkg",
        events=[{"introduced": "0"}, {"fixed": "2.0.1"}],
        aliases=["CVE-2026-0001", "PYSEC-2026-1"],
        summary="Remote code execution in demo-pkg",
        cvss=CVSS_CRITICAL,
        cwes=["CWE-94"],
    ),
    advisory(
        "PYSEC-2026-1",
        "PyPI",
        "demo-pkg",
        events=[{"introduced": "0"}, {"fixed": "2.0.1"}],
        aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
    ),
    advisory(
        "GHSA-dddd-eeee-ffff",
        "PyPI",
        "demo-pkg",
        events=[{"introduced": "1.5"}, {"last_affected": "2.1.0"}],
        summary="Information leak in demo-pkg",
        severity_label="MODERATE",
    ),
    advisory("MAL-2026-100", "PyPI", "evil-pkg", events=[{"introduced": "0"}], summary="Malicious code in evil-pkg"),
    advisory("MAL-2026-101", "PyPI", "popular-lib", versions=["3.3.3"], summary="Compromised release of popular-lib"),
    advisory("GHSA-wwww-xxxx-yyyy", "PyPI", "gone", events=[{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z"),
]
NPM = [
    advisory(
        "GHSA-npm1-npm1-npm1",
        "npm",
        "left-pad",
        events=[{"introduced": "1.0.0"}, {"fixed": "1.3.1"}],
        aliases=["CVE-2026-0002"],
        summary="Prototype pollution in left-pad",
        cvss=CVSS_MEDIUM,
    ),
    advisory("MAL-2026-200", "npm", "@evil/stealer", events=[{"introduced": "0"}], summary="Credential stealer"),
]


# One synthetic advisory per added ecosystem; the package names and versions are made up.
PACKAGIST = [
    advisory(
        "GHSA-php1-demo-0001",
        "Packagist",
        "acme/php-lib",
        events=[{"introduced": "2.0.0"}, {"fixed": "2.3.5"}],
        aliases=["CVE-2026-0003"],
        summary="Remote code execution in acme/php-lib",
        cvss=CVSS_CRITICAL,
        cwes=["CWE-94"],
    )
]
GO = [
    advisory(
        "GO-2026-0001",
        "Go",
        "github.com/acme/gomod",
        events=[{"introduced": "0"}, {"fixed": "1.4.0"}],
        aliases=["CVE-2026-0004"],
        summary="Path traversal in gomod",
        severity_label="HIGH",
    )
]
CRATES = [
    advisory(
        "RUSTSEC-2026-0001",
        "crates.io",
        "acme-crate",
        events=[{"introduced": "0.1.0"}, {"fixed": "0.3.2"}],
        summary="Use after free in acme-crate",
        severity_label="HIGH",
    )
]
MAVEN = [
    advisory(
        "GHSA-mvn1-demo-0001",
        "Maven",
        "org.acme:acme-core",
        events=[{"introduced": "1.0"}, {"fixed": "1.2.5.RELEASE"}],
        aliases=["CVE-2026-0005"],
        summary="Deserialization in acme-core",
        cvss=CVSS_CRITICAL,
    )
]
RUBYGEMS = [
    advisory(
        "GHSA-gem1-demo-0001",
        "RubyGems",
        "acme_gem",
        events=[{"introduced": "0"}, {"fixed": "2.1.0"}],
        summary="SQL injection in acme_gem",
        severity_label="HIGH",
    )
]
NUGET = [
    advisory(
        "GHSA-ngt1-demo-0001",
        "NuGet",
        "Acme.Core",
        events=[{"introduced": "0"}, {"fixed": "3.0.1"}],
        summary="Denial of service in Acme.Core",
        severity_label="MODERATE",
    )
]
PUB = [
    advisory(
        "GHSA-pub1-demo-0001",
        "Pub",
        "acme_dart",
        events=[{"introduced": "0"}, {"fixed": "1.5.0"}],
        summary="Certificate check bypass in acme_dart",
        severity_label="HIGH",
    )
]
ALL = {
    "PyPI": PYPI,
    "npm": NPM,
    "Packagist": PACKAGIST,
    "Go": GO,
    "crates.io": CRATES,
    "Maven": MAVEN,
    "RubyGems": RUBYGEMS,
    "NuGet": NUGET,
    "Pub": PUB,
}


def write_zip(path: Path, records: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))
        bundle.writestr("README.txt", "not an advisory")
    return path


def build(
    directory: Path, *, downloaded_at: str = "", ecosystems: dict[str, list[dict[str, Any]]] | None = None
) -> Path:
    """Build ``osv.sqlite3`` in ``directory`` from synthetic exports, the way ``db update`` does after downloading."""
    stamp = downloaded_at or osvdb._now()
    found = {}
    for ecosystem, records in (ecosystems or {"PyPI": PYPI, "npm": NPM}).items():
        archive = write_zip(directory / "downloads" / f"{ecosystem}.zip", records)
        source = osvdb.Source(
            ecosystem, osvdb.OSV_URL.format(ecosystem=ecosystem), "0" * 64, archive.stat().st_size, stamp
        )
        found[ecosystem] = (archive, source)
    target = directory / osvdb.DB_NAME
    osvdb.build_index(found, target)
    return target
