#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Count the reviewed GitHub Advisory Database advisories (CC BY 4.0) of the Go, Maven, NuGet and RubyGems ecosystems by
CWE family, to choose which weakness families the Phase 4 rules cover first. Reads the archive of the database
(``codeload.github.com/github/advisory-database/tar.gz/refs/heads/main``) as a stream and writes only counts.

    python3 research/hpc/codebench/codebench_p4_advisories.py ARCHIVE.tar.gz OUT.json   (PYTHONPATH with src/)
"""

from __future__ import annotations

import json
import sys
import tarfile
from collections import Counter, defaultdict

from kestrixcodebench.families import families_for_cwes, parse_cwes

ECOSYSTEMS = {"Go": "go", "Maven": "java", "NuGet": "csharp", "RubyGems": "ruby"}


def main() -> int:
    archive, out = sys.argv[1], sys.argv[2]
    advisories: Counter[str] = Counter()
    families: dict[str, Counter[str]] = defaultdict(Counter)
    cwes: dict[str, Counter[str]] = defaultdict(Counter)
    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            if (
                not member.isfile()
                or "/advisories/github-reviewed/" not in member.name
                or not member.name.endswith(".json")
            ):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            record = json.load(handle)
            if record.get("withdrawn"):
                continue
            ecosystems = {
                ECOSYSTEMS[a["package"]["ecosystem"]]
                for a in record.get("affected", [])
                if a.get("package", {}).get("ecosystem") in ECOSYSTEMS
            }
            ids = (record.get("database_specific") or {}).get("cwe_ids") or []
            numbers = parse_cwes(ids)
            fams = sorted(families_for_cwes(numbers)) or ["(none of the families)"]
            for eco in ecosystems:
                advisories[eco] += 1
                families[eco].update(fams)
                cwes[eco].update(f"CWE-{n}" for n in numbers)
    body = {
        "source": "GitHub Advisory Database, reviewed advisories (CC BY 4.0), archive of the main branch",
        "advisories": dict(advisories),
        "by_family": {eco: dict(c.most_common()) for eco, c in families.items()},
        "top_cwes": {eco: dict(c.most_common(15)) for eco, c in cwes.items()},
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps(body["advisories"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
