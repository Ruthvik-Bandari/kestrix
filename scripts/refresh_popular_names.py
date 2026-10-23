# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Refresh the bundled popular-package names (``kestrix_scan/popular_names.json``) by hand.

Run from the repo root: ``python3 scripts/refresh_popular_names.py``. It makes real requests (PyPI list from
hugovk.dev, npm list from raw.githubusercontent.com, crates.io API at 1 request per second with an identifying
User-Agent, Packagist API), so it is a manual step and never part of the tests or CI. The scanner itself reads
only the bundled file and opens no sockets.

Options: ``--top N`` names kept per ecosystem (default 5000); ``--tail-dir DIR`` also writes ranks N+1 to
N+``--tail`` (default 5000) of each ecosystem there as ``tail-<ecosystem>.txt``, for false-positive
measurement only (never bundled); ``--out FILE`` the snapshot to write.

Stdlib only. Names are stored normalized (``kestrix_scan.popular.normalize``) in rank order, most popular first;
the file keeps no download counts. Licences and sources: ``docs/research/dataset-licenses.md``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "packages" / "kestrix-scan" / "src" / "kestrix_scan" / "popular_names.json"
USER_AGENT = "kestrix-scan-refresh (https://github.com/Ruthvik-Bandari/kestrix; bandari.ru@northeastern.edu)"
PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
CRATES_URL = "https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"
PACKAGIST_URL = "https://packagist.org/explore/popular.json?per_page=100&page={page}"
LICENCES = {
    "PyPI": "no licence file in hugovk/top-pypi-packages; names are public download-ranking facts (ClickHouse PyPI dataset)",
    "npm": "MIT, Titus Wormer (wooorm/npm-high-impact)",
    "crates.io": "no data licence stated; crates.io API policy (1 request per second, identifying User-Agent) followed",
    "Packagist": "no data licence stated; public API",
}


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 - fixed https URLs above
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        data: bytes = response.read()
    return data


def _normalize(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name)
    if ecosystem == "crates.io":
        return name.replace("_", "-")
    return name


def _pypi(count: int) -> list[str]:
    rows = json.loads(_get(PYPI_URL))["rows"]
    return [row["project"] for row in rows[:count]]


def _npm(count: int) -> list[str]:
    return re.findall(r"^\s*'([^']+)',?\s*$", _get(NPM_URL).decode(), re.M)[:count]


def _paged(url: str, key: str, count: int, delay: float) -> list[str]:
    names: list[str] = []
    page = 1
    while len(names) < count:
        data: dict[str, Any] = json.loads(_get(url.format(page=page)))
        rows = data[key]
        if not rows:
            break
        names.extend(row["name"] for row in rows)
        page += 1
        time.sleep(delay)
    return names[:count]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=5000)
    parser.add_argument("--tail", type=int, default=5000)
    parser.add_argument("--tail-dir", type=Path)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    want = args.top + (args.tail if args.tail_dir else 0)
    fetched = {
        "PyPI": _pypi(want),
        "npm": _npm(want),
        "crates.io": _paged(CRATES_URL, "crates", want, 1.1),
        "Packagist": _paged(PACKAGIST_URL, "packages", want, 0.5),
    }
    urls = {
        "PyPI": PYPI_URL,
        "npm": NPM_URL,
        "crates.io": CRATES_URL.split("?", maxsplit=1)[0],
        "Packagist": PACKAGIST_URL.split("?", maxsplit=1)[0],
    }
    names: dict[str, list[str]] = {}
    for ecosystem, raw in fetched.items():
        seen: dict[str, None] = {}
        for item in raw:
            seen.setdefault(_normalize(ecosystem, item))
        ordered = list(seen)
        names[ecosystem] = ordered[: args.top]
        if args.tail_dir:
            args.tail_dir.mkdir(parents=True, exist_ok=True)
            (args.tail_dir / f"tail-{ecosystem}.txt").write_text("\n".join(ordered[args.top :]) + "\n")
        print(f"{ecosystem}: {len(names[ecosystem])} kept of {len(raw)} fetched", file=sys.stderr)
    snapshot = {
        "generated": date.today().isoformat(),
        "sources": {eco: {"url": urls[eco], "licence": LICENCES[eco], "count": len(names[eco])} for eco in names},
        "names": names,
    }
    args.out.write_text(json.dumps(snapshot, separators=(",", ":"), ensure_ascii=True) + "\n")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
