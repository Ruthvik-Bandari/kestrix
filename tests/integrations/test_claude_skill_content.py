# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The packaged Claude skill is well formed and agrees with the CLI and the source it describes."""

import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import typer

from kestrix.bitcoin.models import Risk
from kestrix.cli import app
from kestrix.detect.diagnose import Family
from kestrix.detect.workflow import Outcome
from kestrix.integrations.skill import SKILL_NAME, skill_files
from kestrix.mail import intent
from kestrix.webcheck import checks

SRC = Path(__file__).resolve().parents[2] / "src" / "kestrix"
FILES = {str(path): data.decode("utf-8") for path, data in skill_files()}
SKILL_MD = FILES["SKILL.md"]


def _frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, "SKILL.md must start with a --- frontmatter block"
    fields = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(":")
        assert sep and re.fullmatch(r"[a-z_-]+", key), f"unexpected frontmatter line: {line!r}"
        fields[key] = value.strip()
    return fields


def test_frontmatter_has_a_valid_name_and_description():
    fields = _frontmatter(SKILL_MD)
    assert set(fields) == {"name", "description"}
    assert fields["name"] == SKILL_NAME
    assert len(fields["name"]) <= 64 and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fields["name"])
    description = fields["description"]
    assert 0 < len(description) <= 1024
    assert "<" not in description and ">" not in description
    for trigger in ("email", ".eml", "link", "file", "website", "Sigma", "Bitcoin", "not own"):
        assert trigger in description


def test_skill_md_stays_focused_and_credits_the_author():
    assert len(SKILL_MD.splitlines()) < 300
    assert "Kestrix by Ruthvik Bandari — https://github.com/Ruthvik-Bandari/kestrix" in SKILL_MD
    for path in re.findall(r"`(reference/[a-z-]+\.md)`", SKILL_MD):
        assert path in FILES, f"SKILL.md points at a missing file: {path}"
    assert {path for path in FILES if path != "SKILL.md"} <= set(re.findall(r"`(reference/[a-z-]+\.md)`", SKILL_MD))


def _kestrix_invocations(text: str) -> list[list[str]]:
    snippets: list[str] = []
    for block in re.findall(r"^[ \t]*```[a-z]*\n(.*?)^[ \t]*```", text, re.S | re.M):
        snippets += block.replace("\\\n", " ").splitlines()
    snippets += re.findall(r"`([^`\n]+)`", re.sub(r"^[ \t]*```.*?^[ \t]*```", "", text, flags=re.S | re.M))
    found = []
    for snippet in snippets:
        line = snippet.strip().removeprefix("$ ").removeprefix("uv run ")
        if line.startswith("kestrix "):
            found.append(shlex.split(line, comments=True)[1:])
    return found


def _resolve(argv: list[str]) -> tuple[Any, list[str]]:
    """Walk the Typer command tree (Typer >= 0.20 vendors click, so groups are found by their ``commands``)."""
    command: Any = typer.main.get_command(app)
    rest = list(argv)
    while hasattr(command, "commands") and rest and rest[0] in command.commands:
        command = command.commands[rest.pop(0)]
    return command, rest


INVOCATIONS = [args for text in FILES.values() for args in _kestrix_invocations(text)]


def test_the_skill_references_many_commands():
    groups = {args[0] for args in INVOCATIONS if args}
    assert {"version", "mail", "forensics", "webcheck", "detect", "bitcoin"} <= groups
    assert len(INVOCATIONS) >= 20


@pytest.mark.parametrize("argv", INVOCATIONS, ids=lambda argv: " ".join(argv)[:60])
def test_every_referenced_command_and_option_exists(argv):
    command, rest = _resolve(argv)
    if hasattr(command, "commands"):  # a bare group mention such as `kestrix detect`
        assert rest in ([], ["..."]), f"`kestrix {' '.join(argv)}` does not name a command"
        return
    known = {opt for param in command.params for opt in [*param.opts, *param.secondary_opts]}
    for token in rest:
        if token.startswith("--"):
            assert token.split("=", 1)[0] in known, f"unknown option {token} in `kestrix {' '.join(argv)}`"


def _catalog(name: str, pattern: str = r"^\| `([a-z_.]+)` \|") -> set[str]:
    return set(re.findall(pattern, FILES[f"reference/{name}"], re.M)) - {"id"}  # minus the header row


def _source(package: str, pattern: str) -> set[str]:
    return {m for path in (SRC / package).glob("*.py") for m in re.findall(pattern, path.read_text())}


def test_mail_catalog_matches_the_source():
    ids = _source("mail", r'"(mail\.[a-z_]+\.[a-z_]+)"')
    ids |= {f"mail.intent.{family.name}" for family in intent._FAMILIES}
    assert len(ids) >= 30
    assert _catalog("findings-mail.md") == ids


def test_forensics_catalog_matches_the_source():
    ids = _source("forensics", r'(?:_finding|_hit)\(\s*"([a-z_]+)"') | _source("forensics", r'\bid="([a-z_]+)"')
    assert len(ids) >= 20
    assert _catalog("findings-forensics.md") == ids


def test_webcheck_catalog_matches_the_source():
    ids = set(re.findall(r'"([a-z_]+\.[a-z_]+)"', (SRC / "webcheck" / "checks.py").read_text()))
    ids |= {f"tls.{status}" for status in checks._TLS_TEXT}
    assert len(ids) >= 30
    assert _catalog("findings-webcheck.md") == ids


def test_detect_vocabulary_matches_the_source():
    text = FILES["reference/detect.md"]
    outcomes = set(re.findall(r"^\| `([a-z_]+)` \| \d+ \|", text, re.M))
    assert outcomes == {outcome.value for outcome in Outcome}
    diagnose = (SRC / "detect" / "diagnose.py").read_text()
    codes = {
        c for group in re.findall(r"Family\.\w+,\s*\(([^)]*)\)", diagnose, re.S) for c in re.findall(r'"(\w+)"', group)
    }
    rows = re.findall(r"^\| `(\w+)` \| ((?:`\w+`(?:, )?)+) \|", text, re.M)
    rows = [row for row in rows if row[0] != "family"]
    assert {family for family, _ in rows} == {family.value for family in Family}
    assert {code for _, listed in rows for code in re.findall(r"`(\w+)`", listed)} == codes
    workflow = (SRC / "detect" / "workflow.py").read_text()
    failures = set(re.findall(r'failures\.append\("(\w+)"\)', workflow)) | set(
        re.findall(r'return \["(\w+)"\]', workflow)
    )
    section = text.split("## Validation policy failures", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `(\w+)` \|", section, re.M)) == failures


def test_bitcoin_risk_levels_match_the_source():
    listed = set(
        re.findall(r"^\| [^|]+ \| `(\w+)` \| `(?:exposed|not_exposed|unknown)` \|", FILES["reference/bitcoin.md"], re.M)
    )
    assert listed == {risk.value for risk in Risk}
