# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Every registry rule is listed in ``tool.driver.rules`` so ``ruleIndex`` values are stable.
``security-severity`` follows GitHub's convention: a number from 0.0 to 10.0 written as a string.
Results carry only what the report carries; secret snippets are already redacted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

from .about import ATTRIBUTION, __version__
from .models import Finding, ScanReport
from .registry import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Ruthvik-Bandari/kestrix"
DOCS_URI = f"{INFORMATION_URI}/blob/main/docs/modules/code.md"
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rules() -> list[dict[str, Any]]:
    return [
        {
            "id": rule.id,
            "name": "".join(part.capitalize() for part in rule.id.replace(".", "_").split("_")),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.why},
            "help": {"text": rule.fix, "markdown": f"**Why:** {rule.why}\n\n**Fix:** {rule.fix}"},
            "helpUri": f"{DOCS_URI}#rules",
            "defaultConfiguration": {"level": _LEVEL[rule.severity]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[rule.severity],
                "precision": rule.confidence,
                "tags": ["security", rule.cwe],
            },
        }
        for rule in RULES.values()
    ]


def _code_flows(finding: Finding) -> list[dict[str, Any]]:
    """The taint trace as one SARIF thread flow, source first and sink last."""
    uri = quote(finding.path)
    locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"},
                    "region": {"startLine": step.line},
                },
                "message": {"text": step.note},
            }
        }
        for step in finding.trace
    ]
    return [{"threadFlows": [{"locations": locations}]}]


def _result(finding: Finding, index: dict[str, int]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": index[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.message} Fix: {finding.fix}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path), "uriBaseId": "SRCROOT"},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "endLine": finding.end_line,
                        "snippet": {"text": finding.snippet},
                    },
                }
            }
        ],
        "partialFingerprints": {"kestrixFingerprint/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe": finding.cwe,
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }
    if finding.trace:
        result["codeFlows"] = _code_flows(finding)
    return result


def to_sarif(report: ScanReport) -> dict[str, Any]:
    index = {rule_id: position for position, rule_id in enumerate(RULES)}
    results = [_result(finding, index) for finding in report.findings]
    root_uri = Path(report.root).as_uri().rstrip("/") + "/"
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kestrix",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": _rules(),
                    }
                },
                "originalUriBaseIds": {"SRCROOT": {"uri": root_uri}},
                "results": results,
                "properties": {"generated_by": ATTRIBUTION, "suppressed": report.suppressed},
            }
        ],
    }
