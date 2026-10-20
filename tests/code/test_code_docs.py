# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The rules table in docs/modules/code.md matches the rule registry."""

import importlib.util
from pathlib import Path
from types import ModuleType

from kestrix.code.rules import CLEAN_ROOM, RULES

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


def test_every_rule_has_a_provenance_note() -> None:
    for rule in RULES.values():
        assert rule.sources, f"{rule.id} has no documentation sources"
        assert all(url.startswith("https://") for url in rule.sources), rule.id
        assert rule.cwe_url == f"https://cwe.mitre.org/data/definitions/{rule.cwe.removeprefix('CWE-')}.html"


def test_provenance_page_is_current() -> None:
    generator = _generator()
    page = (ROOT / "docs" / "modules" / "code-rules-provenance.md").read_text(encoding="utf-8")
    assert generator.provenance() == page
    for rule in RULES.values():
        section = page.split(f"## `{rule.id}`", 1)[1].split("\n## ", 1)[0]
        assert rule.cwe_url in section and CLEAN_ROOM in section
        assert all(url in section for url in rule.sources)
