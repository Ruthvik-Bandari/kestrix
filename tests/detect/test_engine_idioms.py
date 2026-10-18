# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""ADR 0002 idioms verified on the pinned Elasticsearch: conversion success is not proof."""

import os

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Event
from kestrix.detect.mapping import FieldMapping, to_lucene
from kestrix.detect.rule import parse_rule

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
MAPPING = FieldMapping(
    "ecs",
    {
        "Image": "process.executable",
        "OriginalFileName": "process.pe.original_file_name",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "User": "user.name",
    },
)

pytestmark = pytest.mark.engine


@pytest.fixture(scope="module")
def es():
    engine = Elasticsearch(ES_URL)
    yield engine
    engine.close()


def _rule(detection: str):
    return parse_rule("title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n" + detection)


def _proc(image="C:\\x\\other.exe", ofn="other.exe", cmd="", parent="C:\\x\\p.exe", user="LAB\\a"):
    return {
        "process": {
            "executable": image,
            "pe": {"original_file_name": ofn},
            "command_line": cmd,
            "parent": {"executable": parent},
        },
        "user": {"name": user},
    }


def _matched(es, rule, rows):
    events = [Event(f"e{i}", "unknown", None, data) for i, data in enumerate(rows)]
    with es.replay_index(events) as index:
        return es.search_ids(index, to_lucene(rule, MAPPING)).matched_ids


def test_list_of_maps_is_or_of_and_maps(es):
    rule = _rule(
        "  sel:\n"
        "    - Image|endswith: '\\certutil.exe'\n"
        "    - OriginalFileName: 'CertUtil.exe'\n"
        "      CommandLine|contains: 'decode'\n"
        "  condition: sel\n"
    )
    rows = [
        _proc(image="C:\\Windows\\certutil.exe"),  # first map
        _proc(ofn="CertUtil.exe", cmd="x -decode y"),  # second map, both fields
        _proc(ofn="CertUtil.exe", cmd="x -encode y"),  # second map, one field only
        _proc(),  # neither
    ]
    assert _matched(es, rule, rows) == {"e0", "e1"}


def test_contains_all_requires_every_value(es):
    rule = _rule("  sel:\n    CommandLine|contains|all: ['-urlcache', 'http']\n  condition: sel\n")
    rows = [
        _proc(cmd="certutil -urlcache -f http://h/x"),
        _proc(cmd="certutil -urlcache -f C:\\x"),
        _proc(cmd="curl http://h/x"),
    ]
    assert _matched(es, rule, rows) == {"e0"}


def test_quantifiers_over_selection_patterns(es):
    rule = _rule(
        "  selection_img: {Image|endswith: '\\certutil.exe'}\n"
        "  selection_cli: {CommandLine|contains: 'urlcache'}\n"
        "  filter_main: {ParentImage|endswith: '\\explorer.exe'}\n"
        "  filter_optional: {User|startswith: 'NT AUTHORITY'}\n"
        "  condition: all of selection_* and not 1 of filter_*\n"
    )
    hit = {"image": "C:\\w\\certutil.exe", "cmd": "-urlcache"}
    rows = [
        _proc(**hit),  # both selections, no filter
        _proc(image="C:\\w\\certutil.exe"),  # one selection only
        _proc(**hit, parent="C:\\Windows\\explorer.exe"),  # first filter
        _proc(**hit, user="NT AUTHORITY\\SYSTEM"),  # second filter
    ]
    assert _matched(es, rule, rows) == {"e0"}


def test_one_of_them(es):
    rule = _rule("  a: {Image|endswith: '\\a.exe'}\n  b: {Image|endswith: '\\b.exe'}\n  condition: 1 of them\n")
    rows = [_proc(image="C:\\a.exe"), _proc(image="C:\\b.exe"), _proc(image="C:\\c.exe")]
    assert _matched(es, rule, rows) == {"e0", "e1"}
