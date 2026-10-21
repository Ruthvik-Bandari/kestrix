# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the email benchmark tests."""

from pathlib import Path

import pytest
from mailbench_data import make_sources

from kestrixmailbench.sources import Source


@pytest.fixture
def sources(tmp_path: Path) -> tuple[Path, tuple[Source, ...]]:
    raw = tmp_path / "rawdir"
    return raw, make_sources(raw)
