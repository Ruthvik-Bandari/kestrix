# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Pinned vulnerability-data sources for slice C5 (``docs/research/code-vuln-ml-plan.md``).

Archive sources are pinned by Zenodo record, exact file name, size and MD5 (from
``https://zenodo.org/api/records/<id>``) plus the SHA-256 computed on the first verified
download. Git sources are pinned by commit. Changing a pin is a dataset version change:
update ``research/results/sources.md`` and re-run ``acquire`` and ``qc``.
"""

from __future__ import annotations

from dataclasses import dataclass

from kestrixbench.sources import Source as GitSource


@dataclass(frozen=True)
class Artifact:
    filename: str
    url: str
    size: int
    md5: str
    sha256: str | None  # None only until the first verified download; qc refuses an unpinned file


@dataclass(frozen=True)
class ArchiveSource:
    name: str
    title: str
    revision_label: str
    doi: str
    record_url: str
    license_spdx: str
    allowed_use: str
    attribution: str
    artifacts: tuple[Artifact, ...]


ZENODO = "https://zenodo.org/api/records"

ARCHIVES: tuple[ArchiveSource, ...] = (
    ArchiveSource(
        name="cvefixes",
        title="CVEfixes: Automatically Collected Vulnerabilities and Their Fixes from Open-Source Software",
        revision_label="v1.0.8 (2024-07-28)",
        doi="10.5281/zenodo.13118970",
        record_url="https://zenodo.org/records/13118970",
        license_spdx="CC-BY-4.0",
        allowed_use="Data under CC BY 4.0 (collection code MIT). Mined code keeps each project's own license.",
        attribution="Bhandari, Naseer and Moonen (2021), CVEfixes, PROMISE '21; Moonen and Vidziunas, v1.0.8",
        artifacts=(
            Artifact(
                filename="CVEfixes_v1.0.8.zip",
                url=f"{ZENODO}/13118970/files/CVEfixes_v1.0.8.zip/content",
                size=12708711268,
                md5="4586a358977acfa4c60b1a2cdd096221",
                sha256="6acd55aaeb7ffcfc20fdcebf7df88d206f9892ef64b0f2a2e06864d5b44b3a83",
            ),
        ),
    ),
    ArchiveSource(
        name="morefixes",
        title="MoreFixes: Largest CVE dataset with fixes",
        revision_label="v4, dump 2026-06-20 (CVEs to 2026-06-02)",
        doi="10.5281/zenodo.20776007",
        record_url="https://zenodo.org/records/20776007",
        license_spdx="CC-BY-4.0",
        allowed_use="Data under CC BY 4.0. Mined code keeps each project's own license (the record says so).",
        attribution="Akhoundali, Rahim Nouri, Rietveld and Gadyatskaya (2024), MoreFixes, PROMISE '24",
        artifacts=(
            Artifact(
                filename="dump-2026-06-20.sql.gz",
                url=f"{ZENODO}/20776007/files/dump-2026-06-20.sql.gz/content",
                size=3472298400,
                md5="bdff6120f1e65626c77d42656162316e",
                sha256="5f134e11f43844bbad020030ee9c496d9c036d1da07bf038678c1aba8e148b42",
            ),
            Artifact(
                filename="patch-files2026-06-20.zip",
                url=f"{ZENODO}/20776007/files/patch-files2026-06-20.zip/content",
                size=3000621180,
                md5="c314e8d0fc866301b2d08aef4e6e89fd",
                sha256="52d0b030ab9cb01a5443e8f65f21f2a12406a535f06b6e2d79ee4ef95ed34530",
            ),
        ),
    ),
)

GIT_SOURCES: tuple[GitSource, ...] = (
    GitSource(
        name="ghsa",
        url="https://github.com/github/advisory-database.git",
        commit="f192b634af70bbe4cbe055f5a0e45b62da28b910",
        revision_label="main @ 2026-10-19",
        license_spdx="CC-BY-4.0",
        license_file="LICENSE.md",
        allowed_use="Use, share and adapt with attribution (CC BY 4.0). Only reviewed PyPI and npm advisories are read.",
        attribution="GitHub, Inc. and the GitHub Advisory Database contributors",
        paths=("advisories/github-reviewed",),
    ),
    GitSource(
        name="sven",
        url="https://github.com/eth-sri/sven.git",
        commit="e8449a0d54a5ae0bbdc6bb236330b8c7ec71df57",
        revision_label="master @ 2024-07-14",
        license_spdx="MIT",
        license_file="LICENSE.txt",
        allowed_use="Use, copy, modify and redistribute with the MIT notice. Functions keep their projects' licenses.",
        attribution="He and Vechev (2023), Large Language Models for Code: Security Hardening and Adversarial Testing, CCS '23",
        paths=("data_train_val",),
    ),
)

NAMES: tuple[str, ...] = tuple(s.name for s in ARCHIVES) + tuple(s.name for s in GIT_SOURCES)


def archive(name: str) -> ArchiveSource:
    for source in ARCHIVES:
        if source.name == name:
            return source
    raise KeyError(name)


def git_source(name: str) -> GitSource:
    for source in GIT_SOURCES:
        if source.name == name:
            return source
    raise KeyError(name)
