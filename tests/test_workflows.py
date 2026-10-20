# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Every GitHub Action the repository uses is pinned to a full commit SHA with its tag noted beside it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def test_actions_are_pinned_by_sha():
    uses = [
        (path.name, line.strip())
        for path in WORKFLOWS
        for line in path.read_text().splitlines()
        if re.match(r"\s*(?:-\s+)?uses:", line)
    ]
    assert len(uses) > 10
    for name, line in uses:
        assert re.fullmatch(r"(?:-\s+)?uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(?:\.\d+)*", line), (name, line)


def test_release_publishes_with_trusted_publishing_only():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert 'tags: ["v*"]' in text and "environment:\n      name: pypi" in text
    assert "id-token: write" in text and "attest-build-provenance" in text
    assert "password" not in text and "secrets." not in text
