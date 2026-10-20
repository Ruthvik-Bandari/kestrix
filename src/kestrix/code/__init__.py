# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Local, rule-based security scanning of source code (ADR 0005, slice C1).

    from kestrix.code import exit_code, scan

    report = scan(["src"], fail_on="high")
    for finding in report.findings:
        print(finding.path, finding.line, finding.rule_id, finding.fix)
    raise SystemExit(exit_code(report))

Files are read as data: nothing is imported, executed or sent off the machine.

Since ADR 0006 the scanner is the zero-dependency ``kestrix-scan`` package (``kestrix_scan``). This
module re-exports its public API. The old submodules stay importable as aliases of the
``kestrix_scan`` modules: ``kestrix.code.models``, ``.analyze``, ``.hook``, ``.sarif``, ``.walk``,
``.secrets``, ``.python_rules``, and ``.rules`` for ``kestrix_scan.registry``.
"""

import importlib
import sys

from kestrix_scan import *  # noqa: F403
from kestrix_scan import __all__ as __all__
from kestrix_scan import scan as scan

_ALIASES = {
    "analyze": "analyze",
    "hook": "hook",
    "models": "models",
    "python_rules": "python_rules",
    "rules": "registry",
    "sarif": "sarif",
    "secrets": "secrets",
    "walk": "walk",
}
for _old, _new in _ALIASES.items():
    sys.modules.setdefault(f"{__name__}.{_old}", importlib.import_module(f"kestrix_scan.{_new}"))
del _old, _new
