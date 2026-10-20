# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Kestrix code scanner: local, rule-based security checks for Python code and hard-coded secrets.

    import kestrix_scan

    config = kestrix_scan.load_config("src")       # [tool.kestrix] or .kestrix.toml, if any
    report = kestrix_scan.scan(["src"], config=config, fail_on="high")
    for finding in report.findings:
        print(finding.path, finding.line, finding.rule_id, finding.fix)
    print(report.to_json())
    raise SystemExit(kestrix_scan.exit_code(report))

Files are read as data: nothing is imported, executed or sent off the machine. There are no
runtime dependencies on Python 3.11 and newer (``tomli`` on 3.10).

The names below load their modules on first use, so importing ``kestrix_scan`` (as the pytest
plugin does on every pytest run) costs almost nothing.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from .about import ATTRIBUTION, __author__, __version__

if TYPE_CHECKING:
    from .analyze import FailOn as FailOn
    from .analyze import exit_code as exit_code
    from .analyze import scan as scan
    from .config import Config as Config
    from .config import load_config as load_config
    from .errors import Reason as Reason
    from .errors import Rejected as Rejected
    from .models import Finding as Finding
    from .models import ScanReport as ScanReport
    from .models import SeverityCounts as SeverityCounts
    from .registry import Rule as Rule
    from .registry import rules as rules

_LAZY = {
    "Config": "config",
    "FailOn": "analyze",
    "Finding": "models",
    "Reason": "errors",
    "Rejected": "errors",
    "Rule": "registry",
    "ScanReport": "models",
    "SeverityCounts": "models",
    "exit_code": "analyze",
    "load_config": "config",
    "rules": "registry",
    "scan": "analyze",
}

__all__ = [
    "ATTRIBUTION",
    "Config",
    "FailOn",
    "Finding",
    "Reason",
    "Rejected",
    "Rule",
    "ScanReport",
    "SeverityCounts",
    "__author__",
    "__version__",
    "exit_code",
    "load_config",
    "rules",
    "scan",
]


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY})
