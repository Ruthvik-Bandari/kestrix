# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from functools import partial
from pathlib import Path

import pytest
from forensics_samples import pe_bytes
from typer.testing import CliRunner

from kestrix.forensics import cli
from kestrix.forensics.analysis import analyze_file

runner = CliRunner()


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "invoice.pdf"
    path.write_bytes(pe_bytes(b"\x00" * 500))
    return path


def test_file_summary(sample: Path) -> None:
    result = runner.invoke(cli.app, ["file", str(sample)])
    assert result.exit_code == 0
    assert hashlib.sha256(sample.read_bytes()).hexdigest() in result.stdout
    assert "Windows program (PE executable)  [extension does not match the content]" in result.stdout
    assert "[HIGH] Extension does not match the content" in result.stdout


def test_file_json(sample: Path) -> None:
    result = runner.invoke(cli.app, ["file", str(sample), "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["hashes"]["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert body["file_type"]["id"] == "pe"


def test_file_too_large_exits_2(sample: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "analyze_file", partial(analyze_file, max_bytes=10))
    result = runner.invoke(cli.app, ["file", str(sample)])
    assert result.exit_code == 2
    assert "input_too_large" in result.output


def test_missing_file_exits_2(tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["file", str(tmp_path / "absent.bin")]).exit_code == 2


def test_url_summary() -> None:
    result = runner.invoke(cli.app, ["url", "http://192.168.0.1/login"])
    assert result.exit_code == 0
    assert "Score:    45/100 (medium)" in result.stdout
    assert "[HIGH] Uses a raw IP address instead of a name" in result.stdout


def test_url_without_findings() -> None:
    result = runner.invoke(cli.app, ["url", "https://www.google.com/"])
    assert result.exit_code == 0
    assert "No findings." in result.stdout


def test_url_json() -> None:
    result = runner.invoke(cli.app, ["url", "https://bit.ly/x", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"][0]["id"] == "url_shortener"


def test_rejected_url_exits_2() -> None:
    result = runner.invoke(cli.app, ["url", "ftp://example.com"])
    assert result.exit_code == 2
    assert "invalid_url" in result.output
