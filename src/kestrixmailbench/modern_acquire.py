# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Modern normal mail: public mailing-list months with their full headers (transfer node, standard library only).

Two public archives are read, each one month at a time with a fixed pause between requests (at least the
``Crawl-delay`` of the site's ``robots.txt``):

* the Apache Software Foundation's Pony Mail API (``lists.apache.org/api/mbox.lua``): ``lists.apache.org`` has no
  ``robots.txt``; ``mail-archives.apache.org`` forbids bots, so its mbox files are not used;
* the GNU project's list archive (``lists.gnu.org/archive/mbox/LIST/YYYY-MM``): ``Crawl-delay: 10``, no path blocked.

Python's ``mail.python.org`` (``/*/export/`` disallowed), Fedora (hyperkitty export strips the headers) and the
kernel's ``lore.kernel.org`` (robots block) were checked and not used. Files are 0600 in 0700 directories; each
download's size and SHA-256 go to ``manifests/modern-manifest.json``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .acquire import Opener, _open, download
from .common import Layout, MailBenchError, file_sha256, now, private_dir, write_json

ASF = "asf"
GNU = "gnu"
YEARS = (2022, 2023, 2024, 2025, 2026)
# Three months a year (spread over the year); 2026 stops at September, the last full month before this run.
MONTHS = {year: (3, 7, 11) if year < 2026 else (3, 6, 9) for year in YEARS}
GNU_MONTHS = {year: (2, 6, 10) if year < 2026 else (2, 6, 9) for year in YEARS}
DELAY_S = {ASF: 3.0, GNU: 11.0}
ASF_LISTS = (
    ("dev", "kafka"),
    ("users", "kafka"),
    ("dev", "spark"),
    ("user", "spark"),
    ("dev", "flink"),
    ("user", "flink"),
    ("dev", "airflow"),
    ("dev", "arrow"),
)
GNU_LISTS = ("emacs-devel", "help-gnu-emacs", "guile-devel", "guile-user", "coreutils", "grub-devel", "bug-bash")


@dataclass(frozen=True)
class Feed:
    source: str
    name: str  # list name, unique per source, used in file names and split groups
    year: int
    month: int
    url: str

    @property
    def filename(self) -> str:
        return f"{self.name}_{self.year}-{self.month:02d}.mbox"


def feeds() -> list[Feed]:
    out: list[Feed] = []
    for local, project in ASF_LISTS:
        for year in YEARS:
            for month in MONTHS[year]:
                url = (
                    "https://lists.apache.org/api/mbox.lua"
                    f"?list={local}&domain={project}.apache.org&d={year}-{month:02d}"
                )
                out.append(Feed(ASF, f"{local}-{project}", year, month, url))
    for name in GNU_LISTS:
        for year in YEARS:
            for month in GNU_MONTHS[year]:
                out.append(
                    Feed(GNU, name, year, month, f"https://lists.gnu.org/archive/mbox/{name}/{year}-{month:02d}")
                )
    return out


def acquire(layout: Layout, only: str | None = None, opener: Opener = _open, sleep: Any = time.sleep) -> dict[str, Any]:
    """Download every missing month (resumable); re-verify present files against the manifest; write it."""
    path = layout.manifests / "modern-manifest.json"
    known: dict[str, Any] = {}
    if path.exists():
        known = {f["filename"]: f for f in json.loads(path.read_text())["files"]}
    files: list[dict[str, Any]] = []
    failed: list[str] = []
    for feed in feeds():
        if only and feed.source != only:
            continue
        dest = layout.raw / "modern" / feed.source / feed.filename
        record = known.get(feed.filename)
        if dest.exists():
            sha = file_sha256(dest)
            if record is not None and record["sha256"] != sha:
                raise MailBenchError(f"{feed.filename}: sha256 does not match the manifest")
            record = record or {"downloaded_at": now(), "last_modified": None}
            record = {**record, "size": dest.stat().st_size, "sha256": sha}
        else:
            try:
                info = download(feed.url, dest, opener)
            except MailBenchError as exc:
                # A month that is missing (404) is an empty month; any other failure is recorded and skipped, so one
                # slow request cannot stop the run. A later run retries it.
                if "404" in str(exc):
                    private_dir(dest.parent)
                    dest.write_bytes(b"")
                    dest.chmod(0o600)
                    info = {"size": 0, "sha256": file_sha256(dest), "last_modified": None}
                else:
                    failed.append(feed.filename)
                    sleep(DELAY_S[feed.source])
                    continue
            record = {"downloaded_at": now(), **info}
            sleep(DELAY_S[feed.source])
        files.append(
            {
                "source": feed.source,
                "list": feed.name,
                "year": feed.year,
                "month": feed.month,
                "filename": feed.filename,
                "url": feed.url,
                **record,
            }
        )
        write_json(path, {"schema_version": 1, "generated_at": now(), "files": files})
    return {"schema_version": 1, "generated_at": now(), "files": files, "failed": failed}
