# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The JSON, SARIF and text reports match the output of the pydantic-based scanner, byte for byte."""

import json
from pathlib import Path

import golden_fixture as golden
import pytest
from cli_support import run

from kestrix_scan import scan
from kestrix_scan.cli import render

GOLDEN = Path(__file__).parent / "golden"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = golden.build(tmp_path.resolve())
    monkeypatch.chdir(root)
    return root


def test_json_report_is_byte_identical(project: Path) -> None:
    report = scan([project], root=project, fail_on="medium")
    text = golden.normalize_text(report.to_json(), report.root) + "\n"
    assert text == (GOLDEN / "report.json").read_text(encoding="utf-8")
    assert list(report.to_dict()) == list(json.loads(text))
    assert report.to_dict()["schema_version"] == 1
    assert report.to_dict()["generated_by"] == "Kestrix by Ruthvik Bandari"


def test_cli_json_output_is_byte_identical(project: Path) -> None:
    result = run("--format", "json", "--fail-on", "medium")
    assert result.exit_code == 1
    assert golden.normalize_text(result.stdout, project.as_posix()) == (GOLDEN / "report.json").read_text(
        encoding="utf-8"
    )


def test_sarif_matches(project: Path) -> None:
    report = scan([project], root=project, fail_on="medium")
    sarif = golden.normalize_sarif(json.loads(render(report, "sarif", color=False)))
    assert sarif == golden.load("report.sarif")


def test_text_matches(project: Path) -> None:
    report = scan([project], root=project, fail_on="medium")
    assert render(report, "text", color=False) + "\n" == (GOLDEN / "report.txt").read_text(encoding="utf-8")
