"""Pinned public data sources for the detection-repair benchmark (plan section 11).

Every source is fixed to an exact commit and carries its license record. Changing a pin is a
dataset version change: update ``docs/data/sources.md`` and re-run acquisition and QC.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    commit: str
    revision_label: str
    license_spdx: str
    license_file: str
    allowed_use: str
    attribution: str
    paths: tuple[str, ...]  # sparse checkout directories; root files are always included


SOURCES: tuple[Source, ...] = (
    Source(
        name="sigma",
        url="https://github.com/SigmaHQ/sigma.git",
        commit="552f3fee420ef232a8e5790c4fae591847e32347",
        revision_label="release r2026-07-01",
        license_spdx="DRL-1.1",
        license_file="LICENSE",
        allowed_use="Use, modify and redistribute rules, including commercially, with author attribution "
        "kept in derived rules and in any match output that displays the rule.",
        attribution="SigmaHQ contributors; per-rule `author` field",
        paths=("rules/windows/process_creation", "regression_data/rules/windows/process_creation"),
    ),
    Source(
        name="otrf",
        url="https://github.com/OTRF/Security-Datasets.git",
        commit="d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        revision_label="master @ 2023-09-20",
        license_spdx="MIT",
        license_file="LICENSE",
        allowed_use="Use, copy, modify and redistribute with the MIT copyright and permission notice.",
        attribution="Open Threat Research Forge (OTRF) Security-Datasets contributors",
        paths=("datasets/atomic/_metadata", "datasets/atomic/windows"),
    ),
    Source(
        name="atomic-red-team",
        url="https://github.com/redcanaryco/atomic-red-team.git",
        commit="388942adbd9641f4dfdcf079d7efe9a75ec0ac43",
        revision_label="master @ 2026-09-05",
        license_spdx="MIT",
        license_file="LICENSE.txt",
        allowed_use="Use, copy, modify and redistribute with the MIT notice. Test definitions are read as "
        "data; executing a test requires a separately authorized, isolated lab.",
        attribution="Red Canary, Atomic Red Team contributors",
        paths=("atomics",),
    ),
)


def by_name(name: str) -> Source:
    for source in SOURCES:
        if source.name == name:
            return source
    raise KeyError(name)
