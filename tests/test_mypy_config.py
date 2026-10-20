# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``uv run mypy`` checks every kestrix_scan module: the [tool.mypy] modules list names each one."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "packages" / "kestrix-scan" / "src" / "kestrix_scan"


def test_every_kestrix_scan_module_is_type_checked():
    listed = set(tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["mypy"]["modules"])
    modules = {"kestrix_scan"} | {f"kestrix_scan.{p.stem}" for p in PACKAGE.glob("*.py") if p.stem != "__init__"}
    assert listed == modules
