# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Refresh the bundled version-exposure data (``src/kestrix/webcheck/data/exposure.json``) by hand.

Run from the repo root: ``uv run python scripts/refresh_exposure_data.py``. It makes real requests to
php.net and raw.githubusercontent.com only, so it is a manual step and not part of the tests or CI.

- PHP (php.net/eol.php and supported-versions.php) and Node.js (nodejs/Release schedule.json) are
  rewritten from their official pages. The script stops without writing if a page no longer parses.
- Every other product and every advisory is curated by hand from the ``source`` URL on its entry.
  The script prints those URLs; open them, compare, edit the JSON, then pass ``--confirm-manual``.
  Only that flag moves ``generated`` (the date reports use to say the data is stale), so the date means
  "a person re-checked everything on this day", not "the script ran".

Options: ``--confirm-manual`` set ``generated`` to today; ``--check`` write nothing, exit 1 if PHP or
Node.js differ from the file.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

import httpx

DATA = Path(__file__).resolve().parent.parent / "src" / "kestrix" / "webcheck" / "data" / "exposure.json"
PHP_EOL = "https://www.php.net/eol.php"
PHP_SUPPORTED = "https://www.php.net/supported-versions.php"
NODE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
_DAY = r"(\d{1,2} [A-Z][a-z]{2} \d{4})"
_EOL_ROW = re.compile(rf"<tr>\s*<td>(\d+\.\d+)</td>\s*<td>\s*{_DAY}", re.S)
_SUPPORTED_ROW = re.compile(
    rf'<tr class="(?:stable|security)">\s*<td>\s*<a href="[^"]*version=(\d+\.\d+)">.*?</td>\s*'
    rf"<td>{_DAY}</td>\s*<td[^>]*>.*?</td>\s*<td>{_DAY}</td>\s*<td[^>]*>.*?</td>\s*<td>{_DAY}</td>",
    re.S,
)


def _iso(text: str) -> str:
    return datetime.strptime(text, "%d %b %Y").date().isoformat()


def _get(url: str) -> str:
    resp = httpx.get(url, timeout=20, follow_redirects=True, headers={"User-Agent": "kestrix-exposure-refresh"})
    resp.raise_for_status()
    return resp.text


def php_branches() -> list[dict[str, str]]:
    eol_rows = _EOL_ROW.findall(_get(PHP_EOL))
    supported = _SUPPORTED_ROW.findall(_get(PHP_SUPPORTED))
    if len(eol_rows) < 10 or not supported:
        sys.exit("php.net pages no longer parse as expected; update the patterns in this script.")
    out = [{"branch": b, "status": "eol", "eol": _iso(d), "source": PHP_EOL} for b, d in eol_rows]
    # A supported branch is listed with the day its security support ends, so it turns end of life after it.
    out += [{"branch": b, "status": "eol", "eol": _iso(sec), "source": PHP_SUPPORTED} for b, _, _, sec in supported]
    return sorted(out, key=lambda e: tuple(int(p) for p in e["branch"].split(".")), reverse=True)


def node_branches() -> list[dict[str, str]]:
    schedule = json.loads(_get(NODE))
    out = [
        {"branch": key.removeprefix("v"), "status": "eol", "eol": entry["end"], "source": NODE}
        for key, entry in schedule.items()
        if entry.get("end")
    ]
    if len(out) < 10:
        sys.exit("The Node.js schedule no longer parses as expected; update this script.")
    return sorted(out, key=lambda e: tuple(int(p) for p in e["branch"].split(".")), reverse=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--confirm-manual", action="store_true", help="I re-checked the manual entries; set generated to today"
    )
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if PHP or Node.js differ")
    args = parser.parse_args()
    data = json.loads(DATA.read_text(encoding="utf-8"))
    fresh = {"php": php_branches(), "node": node_branches()}
    changed = [name for name, branches in fresh.items() if data["products"][name]["branches"] != branches]
    print("Changed from the official pages:", ", ".join(changed) or "nothing")
    if args.check:
        sys.exit(1 if changed else 0)
    for name, branches in fresh.items():
        data["products"][name]["branches"] = branches
    if args.confirm_manual:
        data["generated"] = date.today().isoformat()
    DATA.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Wrote", DATA, "- generated:", data["generated"])
    print("Curated by hand (compare each with its source, then rerun with --confirm-manual):")
    for name, prod in data["products"].items():
        if prod["method"] == "manual":
            print(f"  product {name}: {prod['source']}")
    for adv in data["advisories"]:
        print(f"  advisory {adv['id']}: {adv['source']}")


if __name__ == "__main__":
    main()
