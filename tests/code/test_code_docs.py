# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The rules table in docs/modules/code.md matches the rule registry."""

import importlib.util
from pathlib import Path
from types import ModuleType

from kestrix.code.rules import RULES

ROOT = Path(__file__).resolve().parents[2]


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_code_rules_doc", ROOT / "scripts" / "build_code_rules_doc.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rules_table_is_current() -> None:
    generator = _generator()
    document = (ROOT / "docs" / "modules" / "code.md").read_text(encoding="utf-8")
    assert generator.render(document) == document
    assert all(f"`{rule_id}`" in document for rule_id in RULES)
