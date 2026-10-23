# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``scripts/bitcoin_eval.py``: every category passes, the committed report is current, and the evaluation can fail."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from kestrix.bitcoin.models import Risk

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _evaluation() -> ModuleType:
    sys.path.insert(0, str(SCRIPTS))  # the script imports its vectors module by name
    try:
        spec = importlib.util.spec_from_file_location("bitcoin_eval", SCRIPTS / "bitcoin_eval.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPTS))
    return module


EVAL = _evaluation()


def test_every_category_passes_every_case() -> None:
    report = EVAL.evaluate()
    assert [c["id"] for c in report["categories"] if c["failures"]] == []
    assert report["passed"] == report["cases"] > 400
    assert report["network_used"] is False


def test_committed_report_is_current() -> None:
    assert json.loads(EVAL.REPORT.read_text()) == EVAL.evaluate(), "run `uv run python scripts/bitcoin_eval.py`"


def test_official_vector_files_are_not_empty() -> None:
    assert len(EVAL._load("key_io_valid.json")) == 70
    assert len(EVAL._load("key_io_invalid.json")) == 70
    assert len(EVAL._load("bip341_scriptpubkey.json")["scriptPubKey"]) == 7


def test_the_evaluation_fails_when_taproot_is_rated_low(monkeypatch: pytest.MonkeyPatch) -> None:
    real = EVAL.assess
    monkeypatch.setattr(EVAL, "assess", lambda *a, **k: real(*a, **k).model_copy(update={"risk": Risk.LOW}))
    failing = {c["id"] for c in EVAL.evaluate()["categories"] if c["failures"]}
    assert {"bip341_taproot", "risk_matrix"} <= failing


def test_the_evaluation_fails_when_invalid_addresses_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    real = EVAL.parse_address
    monkeypatch.setattr(EVAL, "parse_address", lambda text: real("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    failing = {c["id"] for c in EVAL.evaluate()["categories"] if c["failures"]}
    assert {"core_invalid", "bip173_bip350_segwit_invalid", "core_wif_keys"} <= failing
