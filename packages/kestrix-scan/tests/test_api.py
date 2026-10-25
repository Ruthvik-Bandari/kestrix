# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The public Python API: names, types, immutability and the typed-package marker."""

import dataclasses
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest

import kestrix_scan

SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"


def test_public_names_resolve() -> None:
    for name in kestrix_scan.__all__:
        assert getattr(kestrix_scan, name) is not None, name
    assert {"scan", "Finding", "ScanReport", "rules", "load_config", "Config", "exit_code"} <= set(kestrix_scan.__all__)
    assert set(kestrix_scan.__all__) <= set(dir(kestrix_scan))
    assert set(kestrix_scan.__all__) == {"ATTRIBUTION", "__author__", "__version__", *kestrix_scan._LAZY}
    with pytest.raises(AttributeError):
        _ = kestrix_scan.no_such_name  # type: ignore[attr-defined]


def test_scan_returns_typed_frozen_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SHELL)
    report = kestrix_scan.scan([tmp_path], root=tmp_path)
    assert isinstance(report, kestrix_scan.ScanReport)
    (finding,) = report.findings
    assert isinstance(finding, kestrix_scan.Finding) and finding.rule_id == "py.subprocess.shell_true"
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.line = 2  # type: ignore[misc]
    assert not hasattr(finding, "__dict__")  # slots
    assert kestrix_scan.exit_code(report) == 1 and kestrix_scan.exit_code(report, "critical") == 0


def test_rules_lists_the_registry_in_order() -> None:
    ids = [rule.id for rule in kestrix_scan.rules()]
    assert ids[0] == "py.exec.eval" and ids[-1] == "swift.storage.userdefaults_secret" and len(ids) == len(set(ids))
    assert all(rule.cwe.startswith("CWE-") and rule.sources for rule in kestrix_scan.rules())


def test_package_is_typed() -> None:
    assert files("kestrix_scan").joinpath("py.typed").is_file()


def test_import_is_light() -> None:
    code = "import sys, kestrix_scan; print(sorted(m for m in sys.modules if m.startswith('kestrix_scan')))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "['kestrix_scan', 'kestrix_scan.about']"


def test_no_third_party_imports() -> None:
    """Importing every module, including the CLI, loads nothing outside the standard library (and tomli on 3.10)."""
    code = (
        "import sys\n"
        "before = set(sys.modules)\n"
        "import kestrix_scan.cli, kestrix_scan.init, kestrix_scan.hook, kestrix_scan.plugin\n"
        "new = {m.split('.')[0] for m in set(sys.modules) - before}\n"
        "stdlib = set(sys.stdlib_module_names)\n"
        "print(sorted(m for m in new if m not in stdlib and m not in {'kestrix_scan', 'tomli', '_distutils_hack'}))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "[]"
