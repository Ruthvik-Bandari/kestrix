import json
import os

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrix.detect.fixtures import Dataset, Event
from kestrix.detect.mapping import FieldMapping
from kestrix.detect.rule import parse_rule
from kestrixbench.b2 import build_prompt, generator, parse

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
RULE = parse_rule(
    "title: t\nid: 00000000-0000-4000-8000-0000000000b2\n"
    "logsource: {category: process_creation, product: windows}\n"
    "detection:\n  sel: {CommandLine|contains: urlcache}\n  condition: sel\n"
)
MAPPING = FieldMapping("m", {"CommandLine": "winlog.event_data.CommandLine"})
DATASET = Dataset(
    "d",
    (
        Event("e1", "malicious", "S1", {"process": {"command_line": "certutil -urlcache SECRETVALUE"}}),
        Event("e2", "benign", None, {"process": {"command_line": "ping localhost"}}),
    ),
    "0" * 64,
)
GOOD = {
    "patch_kind": "mapping",
    "patch": [
        {
            "kind": "mapping",
            "sigma_field": "CommandLine",
            "from_field": "winlog.event_data.CommandLine",
            "to_field": "process.command_line",
        }
    ],
}


def test_prompt_carries_structure_but_no_event_values():
    prompt = build_prompt(RULE, MAPPING, DATASET, [], frozenset())
    assert "process.command_line" in prompt  # observed field names are evidence
    assert "SECRETVALUE" not in prompt and "ping localhost" not in prompt
    assert '"malicious_events": 1' in prompt


def test_parse_accepts_fenced_json_and_drops_out_of_contract_proposals():
    bad_kind = {"patch_kind": "rule", "patch": GOOD["patch"]}  # mapping op in a rule candidate: schema-valid ...
    junk = {"patch_kind": "mapping", "patch": [{"kind": "rm_rf"}]}
    text = "Here you go:\n```json\n" + json.dumps({"candidates": [GOOD, junk, "x", bad_kind]}) + "\n```"
    candidates, dropped = parse(text, RULE, "a" * 64)
    assert [c.patch_kind for c in candidates] == ["mapping", "rule"]  # ... and refused later by apply()
    assert dropped == 2
    assert candidates[0].model_revision.startswith("Qwen/Qwen2.5-Coder-7B-Instruct@")
    assert parse("no json here", RULE, "a" * 64) == ([], 1)
    assert parse('{"candidates": "nope"}', RULE, "a" * 64) == ([], 1)


def test_generator_counts_calls_and_drops():
    stats: dict[str, int] = {}
    propose = generator(lambda prompt: json.dumps({"candidates": [GOOD, {"patch_kind": "?"}]}), stats)
    assert len(propose(RULE, MAPPING, DATASET, [], frozenset())) == 1
    assert stats == {"calls": 1, "valid": 1, "dropped": 1}


@pytest.mark.engine
def test_model_candidate_goes_through_screening_and_validation(tmp_path):
    from kestrix.detect.workflow import run
    from kestrixbench.evaluate import load_case, score
    from kestrixbench.variants import build
    from tests.bench.test_variants import make_root, split_manifest

    def oracle(prompt: str) -> str:  # stands in for the GPU model
        return json.dumps(
            {
                "candidates": [
                    {
                        "patch_kind": "mapping",
                        "patch": [
                            {
                                "kind": "mapping",
                                "sigma_field": "CommandLine",
                                "from_field": "winlog.event_data.CommandLine",
                                "to_field": "process.command_line",
                            }
                        ],
                    }
                ]
            }
        )

    data = make_root(tmp_path)
    es = Elasticsearch(ES_URL)
    try:
        build(data, split_manifest(), {"per_rule": {}}, benign=set(), es=es, seed="s")
        case = next((data / "benchmark/cases/development").glob("*-mapping"))
        manifest, inputs = load_case(case)
        row = score(manifest, run(inputs, es, generator=generator(oracle)))
        assert row["success"] and row["patch_kind"] == "mapping"
    finally:
        es.close()


def test_fetch_script_pins_the_same_model():
    from pathlib import Path

    from kestrixbench.b2 import MODEL_REPO, MODEL_REVISION

    script = (Path(__file__).resolve().parents[2] / "hpc/fetch_model.sh").read_text()
    assert f"REPO={MODEL_REPO}\n" in script and f"REV={MODEL_REVISION}\n" in script
    sbatch = (Path(__file__).resolve().parents[2] / "hpc/b2.sbatch").read_text()
    assert f"{MODEL_REPO.split('/')[1]}@{MODEL_REVISION}" in sbatch
