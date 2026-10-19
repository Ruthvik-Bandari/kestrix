# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Local, rule-based security scanning of source code (ADR 0005, slice C1).

    from kestrix.code import exit_code, scan

    report = scan(["src"], fail_on="high")
    for finding in report.findings:
        print(finding.path, finding.line, finding.rule_id, finding.fix)
    raise SystemExit(exit_code(report))

Files are read as data: nothing is imported, executed or sent off the machine.
"""

from .analyze import exit_code, scan
from .models import Finding, ScanReport

__all__ = ["Finding", "ScanReport", "exit_code", "scan"]
