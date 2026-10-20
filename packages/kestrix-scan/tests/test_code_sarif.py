# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 structure, checked against the keys the schema requires (the schema is not downloaded)."""

from pathlib import Path

from kestrix_scan import scan
from kestrix_scan.registry import RULES
from kestrix_scan.sarif import SECURITY_SEVERITY, to_sarif


def test_sarif_shape(tmp_path: Path) -> None:
    (tmp_path / "a b.py").write_text("import os\ndef f(n):\n    os.system(n)\n")
    sarif = to_sarif(scan([tmp_path], root=tmp_path))
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    (run,) = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Kestrix"
    assert driver["informationUri"] == "https://github.com/Ruthvik-Bandari/kestrix"
    assert [rule["id"] for rule in driver["rules"]] == list(RULES)
    for rule in driver["rules"]:
        assert {"id", "shortDescription", "fullDescription", "help", "properties"} <= rule.keys()
        assert rule["shortDescription"]["text"] and rule["help"]["text"]
        assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0
        assert rule["properties"]["tags"][0] == "security"
        assert rule["properties"]["tags"][1].startswith("CWE-")
    (result,) = run["results"]
    assert {"ruleId", "message", "locations", "partialFingerprints", "level"} <= result.keys()
    assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"] == "py.os.system"
    assert result["level"] == "error" and result["message"]["text"]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "a%20b.py", "uriBaseId": "SRCROOT"}
    assert location["region"]["startLine"] == 3 and location["region"]["startColumn"] == 5
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"].startswith("file:///")
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"].endswith("/")


def test_security_severity_values() -> None:
    severities = {rule.severity: rule for rule in RULES.values()}
    assert SECURITY_SEVERITY == {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
    assert set(severities) == set(SECURITY_SEVERITY)
