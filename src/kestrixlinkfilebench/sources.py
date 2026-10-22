# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The public datasets of the link and file benchmark and how each is read and labelled.

Sizes and SHA-256 are recorded by ``acquire`` on the first download (trust on first use). Not used, on
purpose: OpenPhish and URLhaus (their terms forbid this use), PhishTank (its terms conflict and need a
registration; see ``docs/research/linkfile-benchmark.md``), and every live-malware file set
(MalwareBazaar, VirusShare, SOREL, UNSAFE-DOCS), which this benchmark never downloads.
"""

from __future__ import annotations

from kestrixmailbench.sources import Document, Source, SourceFile

from .common import SEED, seeded_key

PHIUSIIL = "phiusiil"
MAJESTIC = "majestic"
GOVDOCS = "govdocs1"

KIND_PHIUSIIL = "phiusiil_zip"
KIND_MAJESTIC = "majestic_csv"
KIND_GOVDOCS = "govdocs_zip"

GOVDOCS_THREADS = 20
GOVDOCS_BASE = "https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles"


def govdocs_threads(count: int = GOVDOCS_THREADS, seed: str = SEED) -> list[str]:
    """The ``count`` Govdocs1 zip names (of 000 to 999) with the smallest seeded hash, in name order."""
    names = [f"{n:03d}" for n in range(1000)]
    return sorted(sorted(names, key=lambda name: seeded_key(seed, name))[:count])


def _sources() -> tuple[Source, ...]:
    return (
        Source(
            name=PHIUSIIL,
            title="PhiUSIIL Phishing URL (Website) dataset, UCI 967",
            license_spdx="CC-BY-4.0",
            license_note=(
                "CC BY 4.0 per the UCI Machine Learning Repository page; attribution required. Label coding in the "
                "CSV is 1 = legitimate, 0 = phishing (inverted here and tested). Phishing and legitimate URLs were "
                "collected differently, so class differences can be collection artifacts (see the leakage section)."
            ),
            attribution=(
                "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) [Dataset]. UCI Machine Learning "
                "Repository. https://doi.org/10.1016/j.cose.2023.103545 (CC BY 4.0)"
            ),
            landing_url="https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
            files=(
                SourceFile(
                    "phiusiil.zip",
                    "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
                    KIND_PHIUSIIL,
                    "mixed",
                ),
            ),
            documents=(
                Document("uci-967.html", "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"),
            ),
        ),
        Source(
            name=MAJESTIC,
            title="Majestic Million (top one million domains)",
            license_spdx="CC-BY-3.0",
            license_note=(
                "CC BY 3.0 Unported per majestic.com/reports/majestic-million; attribution required. Only domain "
                "names are used, turned into host-root URLs (https://domain/, half with www.); they carry no path or "
                "query, so they stand for popular sites, not for what a legitimate link usually looks like."
            ),
            attribution="Majestic, Majestic Million. https://majestic.com/reports/majestic-million (CC BY 3.0)",
            landing_url="https://majestic.com/reports/majestic-million",
            files=(
                SourceFile(
                    "majestic_million.csv",
                    "https://downloads.majestic.com/majestic_million.csv",
                    KIND_MAJESTIC,
                    "benign",
                ),
            ),
            documents=(Document("majestic-million.html", "https://majestic.com/reports/majestic-million"),),
        ),
        Source(
            name=GOVDOCS,
            title=f"Govdocs1 (Digital Corpora), {GOVDOCS_THREADS} seeded zip threads of 1,000",
            license_spdx="LicenseRef-Govdocs1-freely-redistributable",
            license_note=(
                "Digital Corpora states the documents are freely available for research and, to the best of its "
                "knowledge, freely redistributable; no formal license is named. The files are verbatim copies of US "
                "government web documents and can include malware (not removed), so 'benign' means presumed benign. "
                "Never opened or executed here: read as bytes only. Raw files stay on the cluster."
            ),
            attribution=(
                "Garfinkel, S., Farrell, P., Roussev, V., & Dinolt, G. (2009). Bringing science to digital forensics "
                "with standardized forensic corpora. Digital Investigation, 6, S2-S11 (DFRWS 2009). "
                "https://digitalcorpora.org/corpora/file-corpora/files/"
            ),
            landing_url="https://digitalcorpora.org/corpora/file-corpora/files/",
            files=tuple(
                SourceFile(f"{name}.zip", f"{GOVDOCS_BASE}/{name}.zip", KIND_GOVDOCS, "benign", single_year=True)
                for name in govdocs_threads()
            ),
            documents=(
                Document("digitalcorpora-files.html", "https://digitalcorpora.org/corpora/file-corpora/files/"),
            ),
        ),
    )


SOURCES: tuple[Source, ...] = _sources()
BY_NAME = {source.name: source for source in SOURCES}
