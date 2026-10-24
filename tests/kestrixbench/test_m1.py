# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import os

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrix.detect.mapping import FieldMapping
from kestrix.detect.rule import parse_rule
from kestrixbench.m1 import encode
from kestrixbench.sft import build, reference_repair

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
HEAD = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
HEALTHY = parse_rule(HEAD + "  a: {Image|endswith: '\\\\x.exe'}\n  b: {User: s}\n  condition: a and not b\n")
MAP = FieldMapping("m", {"Image": "process.executable", "User": "user.name"})


def test_reference_repair_recovers_each_fault_kind():
    stale = MAP.with_field("Image", "winlog.event_data.Image")
    assert reference_repair(HEALTHY, stale, HEALTHY, MAP) == {
        "candidates": [
            {
                "patch_kind": "mapping",
                "patch": [
                    {
                        "kind": "mapping",
                        "sigma_field": "Image",
                        "from_field": "winlog.event_data.Image",
                        "to_field": "process.executable",
                    }
                ],
            }
        ]
    }
    flipped = parse_rule(HEAD + "  a: {Image|endswith: '\\\\x.exe'}\n  b: {User: s}\n  condition: a and b\n")
    op = reference_repair(flipped, MAP, HEALTHY, MAP)["candidates"][0]["patch"][0]
    assert op == {"kind": "set_condition", "condition": "a and not b"}
    exact = parse_rule(HEAD + "  a: {Image: '\\\\x.exe'}\n  b: {User: s}\n  condition: a and not b\n")
    op = reference_repair(exact, MAP, HEALTHY, MAP)["candidates"][0]["patch"][0]
    assert op["kind"] == "set_predicate" and op["predicate"]["modifier"] == "endswith"
    assert reference_repair(HEALTHY, MAP, HEALTHY, MAP) == {"candidates": []}


def test_sft_never_reads_the_locked_split(tmp_path):
    with pytest.raises(ValueError, match="locked"):
        build(tmp_path, "test", None)  # type: ignore[arg-type]


class _Tok:
    eos_token = "<e>"

    def apply_chat_template(self, messages, tokenize, add_generation_prompt):
        return "U:" + messages[0]["content"] + "|A:"

    def __call__(self, text, add_special_tokens):
        return {"input_ids": [ord(c) for c in text]}


def test_encode_masks_the_prompt_and_truncates_from_the_left():
    ids, labels, cut = encode(_Tok(), {"prompt": "abc", "completion": "XY"}, max_tokens=100)
    assert not cut and len(ids) == len(labels)
    assert labels[: len("U:abc|A:")] == [-100] * len("U:abc|A:")
    assert labels[-5:] == [ord(c) for c in "XY<e>"]
    ids, labels, cut = encode(_Tok(), {"prompt": "a" * 50, "completion": "XY"}, max_tokens=10)
    assert cut and len(ids) == 10 and labels[-5:] == [ord(c) for c in "XY<e>"]  # the target survives


@pytest.mark.engine
def test_sft_examples_are_valid_and_value_free(tmp_path):
    from kestrixbench.b2 import parse
    from kestrixbench.variants import build as build_variants
    from tests.kestrixbench.test_variants import make_root, split_manifest

    data = make_root(tmp_path)
    manifest = split_manifest()
    manifest["splits"] = {"train": manifest["splits"]["development"], "reserve": []}
    es = Elasticsearch(ES_URL)
    try:
        build_variants(data, manifest, {"per_rule": {}}, benign=set(), es=es, seed="s")
        built, skipped = build(data / "benchmark/cases", "train", es)
        rows = {r["kind"]: r for r in built}
        assert skipped == 0
    finally:
        es.close()
    assert sorted(rows) == ["healthy", "logic", "mapping", "missing_telemetry"]
    assert json.loads(rows["healthy"]["completion"]) == {"candidates": []}
    assert json.loads(rows["missing_telemetry"]["completion"]) == {"candidates": []}
    rule = parse_rule((next((data / "benchmark/cases/train").glob("*-mapping")) / "rule.yml").read_text())
    candidates, dropped = parse(rows["mapping"]["completion"], rule, "a" * 64)
    assert len(candidates) == 1 and dropped == 0 and candidates[0].patch_kind == "mapping"
    assert all("-urlcache" not in r["prompt"].split("EVIDENCE")[1] for r in rows.values())  # no event values


def test_reference_repair_skips_fixes_outside_the_contract():
    added = parse_rule(
        HEAD
        + "  a: {Image|endswith: '\\\\x.exe'}\n  b: {User: s}\n  c: {Company: z}\n  condition: a and not b and not c\n"
    )
    assert reference_repair(HEALTHY, MAP, added, MAP) is None  # a new selection is not a candidate edit
    reshaped = parse_rule(
        HEAD + "  a: {Image|endswith: '\\\\x.exe', CommandLine: q}\n  b: {User: s}\n  condition: a and not b\n"
    )
    assert reference_repair(HEALTHY, MAP, reshaped, MAP) is None  # fields changed inside a selection
    wider = parse_rule(
        HEAD + "  a: {Image|endswith: ['\\\\x.exe', '\\\\y.exe']}\n  b: {User: s}\n  condition: a and not b\n"
    )
    op = reference_repair(HEALTHY, MAP, wider, MAP)["candidates"][0]["patch"][0]
    assert op["kind"] == "set_predicate" and len(op["predicate"]["values"]) == 2
    assert op["predicate"]["values"][1].endswith("y.exe")


def test_reference_targets_must_pass_the_real_contract():
    """Review finding: condition + predicate fixes could total more than 3 AST edits."""
    healthy = parse_rule(
        HEAD + "  a: {Image|endswith: '\\\\x.exe'}\n  b: {User: s}\n  c: {Company: z}\n  condition: (a or b) and c\n"
    )
    broken = parse_rule(
        HEAD + "  a: {Image: 'x.exe'}\n  b: {User: s}\n  c: {Company: z}\n  condition: (a and b) or c\n"
    )
    assert (
        reference_repair(broken, MAP, healthy, MAP) is None
    )  # condition 2 + modifier 1 + values 1 = 4 edits: apply() refuses it
    simple = parse_rule(
        HEAD + "  a: {Image|endswith: '\\\\x.exe'}\n  b: {User: s}\n  c: {Company: z}\n  condition: (a and b) or c\n"
    )
    assert reference_repair(simple, MAP, healthy, MAP)["candidates"][0]["patch"][0]["kind"] == "set_condition"
