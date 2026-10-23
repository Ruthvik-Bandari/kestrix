# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Round-3 (Bandit-gap) changes, judged on the tuning data (see docs/benchmarks/cvefixes.md): a positive and a
negative case for every kept change, and the jQuery rule variant with its switch."""

import textwrap
from pathlib import Path

import pytest

from kestrix_scan import scan
from kestrix_scan.config import from_mapping
from kestrix_scan.js_rules import check_js
from kestrix_scan.python_rules import check_python
from kestrix_scan.registry import Hit


def hits(source: str) -> list[Hit]:
    result = check_python(textwrap.dedent(source), "app.py")
    assert isinstance(result, list), result
    return result


def ids(source: str) -> set[str]:
    return {hit.rule_id for hit in hits(source)}


# ----- standard-library XML parsers in files that handle network data


def test_stdlib_xml_string_parse_in_a_network_file() -> None:
    found = ids("import requests\nimport xml.etree.ElementTree as ET\ndef f(raw):\n    return ET.fromstring(raw)\n")
    assert "py.xml.stdlib_parse" in found
    source = "import flask\nfrom xml.dom import minidom\ndef f(raw):\n    return minidom.parseString(raw)\n"
    assert "py.xml.stdlib_parse" in ids(source)


@pytest.mark.parametrize(
    "source",
    [
        "import xml.etree.ElementTree as ET\ndef f(raw):\n    return ET.fromstring(raw)\n",  # no network or web import
        "import requests\nimport xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n",  # a literal
        "import requests\nimport xml.etree.ElementTree as ET\ndef f(path):\n    return ET.parse(path)\n",  # a file
        "import requests\nimport defusedxml.ElementTree as ET\ndef f(raw):\n    return ET.fromstring(raw)\n",
        "import requests\nimport defusedxml\nimport xml.etree.ElementTree as ET\nET.fromstring(raw)\n",
        "import requests\nfrom lxml import etree\ndef f(raw):\n    return etree.fromstring(raw)\n",  # not stdlib
    ],
)
def test_stdlib_xml_negatives(source: str) -> None:
    assert "py.xml.stdlib_parse" not in ids(source)


# ----- Jinja2 Environment without autoescape


def test_autoescape_default_with_file_loader() -> None:
    found = ids("from jinja2 import Environment, FileSystemLoader\nenv = Environment(loader=FileSystemLoader('t'))\n")
    assert "py.xss.autoescape_off" in found


def test_autoescape_default_in_web_file() -> None:
    found = ids("import flask\nimport jinja2\nenv = jinja2.Environment(loader=jinja2.BaseLoader())\n")
    assert "py.xss.autoescape_off" in found


def test_autoescape_one_finding_per_call() -> None:
    source = "import flask\nimport jinja2\nenv = jinja2.Environment(loader=jinja2.FileSystemLoader('t'))\n"
    assert [hit.rule_id for hit in hits(source)].count("py.xss.autoescape_off") == 1


@pytest.mark.parametrize(
    "source",
    [
        "import jinja2\nenv = jinja2.Environment(autoescape=True)\n",
        "import jinja2\nenv = jinja2.Environment(autoescape=False)\n",  # explicit: not in the rule (no tuning evidence)
        "import jinja2\nenv = jinja2.Environment(autoescape=jinja2.select_autoescape(['html']))\n",
        "import jinja2\nenv = jinja2.Environment(**options)\n",  # the options may set autoescape
        "import jinja2\nenv = jinja2.Environment(loader=jinja2.BaseLoader())\n",  # no web framework, no file loader
    ],
)
def test_autoescape_negatives(source: str) -> None:
    assert "py.xss.autoescape_off" not in ids(source)


# ----- the jQuery form of js.dom.xss_sink has its own rule id and a switch

JQUERY = "function show(el, name) { $(el).html('<b>' + name + '</b>'); }\n"
PLAIN = "function show(el, name) { el.innerHTML = '<b>' + name + '</b>'; }\n"


def js_ids(source: str) -> set[str]:
    result = check_js(source, "app.js")
    assert isinstance(result, list), result
    return {hit.rule_id for hit in result}


def test_jquery_html_has_its_own_rule_id() -> None:
    assert js_ids(JQUERY) == {"js.dom.xss_sink.jquery"}
    assert js_ids(PLAIN) == {"js.dom.xss_sink"}


def scan_ids(tmp_path: Path, **table: object) -> set[str]:
    (tmp_path / "app.js").write_text(JQUERY + PLAIN, encoding="utf-8")
    config = from_mapping({"rules": table}, base=tmp_path) if table else None
    return {finding.rule_id for finding in scan([tmp_path], config=config).findings}


def test_jquery_sinks_on_by_default(tmp_path: Path) -> None:
    assert scan_ids(tmp_path) == {"js.dom.xss_sink", "js.dom.xss_sink.jquery"}


def test_jquery_sinks_can_be_switched_off(tmp_path: Path) -> None:
    assert scan_ids(tmp_path, disable=["js.dom.xss_sink.jquery"]) == {"js.dom.xss_sink"}


def test_disabling_the_parent_disables_the_variant(tmp_path: Path) -> None:
    assert scan_ids(tmp_path, disable=["js.dom.xss_sink"]) == set()


def test_parent_suppression_covers_the_variant(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "function show(el, name) {\n  // kestrix: ignore[js.dom.xss_sink] name is escaped upstream\n"
        "  $(el).html('<b>' + name + '</b>');\n}\n",
        encoding="utf-8",
    )
    report = scan([tmp_path])
    assert not report.findings and report.suppressed == 1
