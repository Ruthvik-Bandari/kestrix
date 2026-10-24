# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the link and file benchmark tests."""

from pathlib import Path

import pytest
from linkfilebench_data import THREADS, write_raw

import kestrixlinkfilebench.files as files_module


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tiny PhiUSIIL, Majestic and Govdocs-style inputs; the real thread list is replaced by two small threads."""
    root = tmp_path / "raw"
    write_raw(root)
    monkeypatch.setattr(files_module, "thread_names", lambda: list(THREADS))
    return tmp_path
