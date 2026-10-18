# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The landing page's "with Kestrix" samples must equal what the code produces today."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "frontend" / "src" / "features" / "landing" / "samples"


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_landing_samples", ROOT / "scripts" / "build_landing_samples.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def _committed(name: str) -> Any:
    return json.loads((SAMPLES / f"{name}.json").read_text())


@pytest.mark.parametrize("name", sorted(GEN.OFFLINE))
def test_offline_sample_matches_current_output(name: str) -> None:
    fresh = json.loads(GEN.dump(GEN.OFFLINE[name]()))
    assert fresh == _committed(name), f"run `uv run python scripts/build_landing_samples.py` to refresh {name}.json"


def test_email_sample_is_flagged_by_real_findings() -> None:
    sample = _committed("email")
    assert sample["report"]["verdict"] == "malicious"
    ids = {f["id"] for f in sample["report"]["findings"]}
    assert {
        "mail.sender.reply_to_mismatch",
        "mail.links.text_href_mismatch",
        "mail.attachments.double_extension",
    } <= ids
    assert sample["message"]["from_address"].endswith(".example")


def test_detect_sample_schema() -> None:
    sample = _committed("detect")
    assert sample["outcome"] in {"repaired", "unchanged", "abstained", "unsupported", "insufficient_evidence"}
    event_ids = {e["event_id"] for e in sample["events"]}
    for phase in ("healthy", "before", "after"):
        counts = sample[phase]["counts"]
        assert set(counts) >= {"tp", "fp", "fn", "tn"}
        assert all(isinstance(v, int) for v in counts.values())
        assert set(sample[phase]["matched"]) <= event_ids
        assert counts["tp"] + counts["fp"] == len(sample[phase]["matched"])
    assert sample["diff"].startswith("--- a/")
    assert sample["patch"]


def test_webcheck_sample_schema() -> None:
    sample = _committed("webcheck")
    assert sample["grade"] in {"A", "B", "C", "D", "F"}
    assert 0 <= sample["score"] <= 100
    assert sample["findings"]
    for finding in sample["findings"]:
        assert finding["severity"] in {"info", "low", "medium", "high"}
        assert finding["id"] and finding["title"]
