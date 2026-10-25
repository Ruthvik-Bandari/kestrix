# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest
from mail_samples import BODY_SENTINEL, message
from typer.testing import CliRunner

from kestrix.cli import app as root_app
from kestrix.mail import cli

runner = CliRunner()


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "msg.eml"
    path.write_bytes(message(headers=[("Reply-To", "pay@other.example")]))
    return path


def test_summary(sample: Path) -> None:
    result = runner.invoke(cli.app, ["analyze", str(sample)])
    assert result.exit_code == 0
    assert "Verdict:  suspicious (heuristic score 15/100)" in result.stdout
    assert "[MEDIUM] Replies go to a different domain than the sender" in result.stdout
    assert "evidence: From domain example.com; Reply-To domain other.example" in result.stdout
    assert "not a probability" in result.stdout
    assert BODY_SENTINEL not in result.stdout


def test_json(sample: Path) -> None:
    result = runner.invoke(cli.app, ["analyze", str(sample), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["verdict"] == "suspicious"


def test_options(tmp_path: Path) -> None:
    path = tmp_path / "brand.eml"
    path.write_bytes(
        message(sender='"PayPal" <a@evil.example>', auth=("other.example; dmarc=pass", "mx.mine.example; dmarc=fail"))
    )
    args = [
        "analyze",
        str(path),
        "--protected-domain",
        "paypal.com",
        "--trusted-authserv-id",
        "mx.mine.example",
        "--json",
    ]
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0
    assert {f["id"] for f in json.loads(result.stdout)["findings"]} == {
        "mail.sender.display_name_brand",
        "mail.auth.dmarc_fail",
    }


def test_clean_message_without_findings(tmp_path: Path) -> None:
    path = tmp_path / "clean.eml"
    path.write_bytes(message())
    result = runner.invoke(cli.app, ["analyze", str(path), "--trusted-authserv-id", "mx.example.net"])
    assert result.exit_code == 0
    assert "No findings." in result.stdout


def test_rejected_input_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "garbage.eml"
    path.write_bytes(b"\x00\x01garbage")
    result = runner.invoke(cli.app, ["analyze", str(path)])
    assert result.exit_code == 2
    assert "Rejected (invalid_input)" in result.output


def test_oversized_file_is_refused_before_reading(sample: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "MAX_MESSAGE_BYTES", 10)
    monkeypatch.setattr(cli, "analyze_stream", lambda *_, **__: pytest.fail("the file must not be read"))
    result = runner.invoke(cli.app, ["analyze", str(sample)])
    assert result.exit_code == 2
    assert "input_too_large" in result.output


def test_invalid_option_exits_2(sample: Path) -> None:
    result = runner.invoke(cli.app, ["analyze", str(sample), "--protected-domain", "not a domain"])
    assert result.exit_code == 2


def test_missing_file_exits_2(tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["analyze", str(tmp_path / "absent.eml")]).exit_code == 2


def test_registered_on_the_root_command(sample: Path) -> None:
    result = runner.invoke(root_app, ["mail", "analyze", str(sample), "--json"])
    assert result.exit_code == 0
    assert "Explainable analysis of saved email messages" in runner.invoke(root_app, ["--help"]).stdout
