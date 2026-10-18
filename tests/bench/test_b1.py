import os

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrix.detect.rule import parse_condition
from kestrixbench.b1 import build_memory, edit_signature

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
NAMES = ["a", "b", "c"]


@pytest.mark.parametrize(
    ("before", "after", "signature"),
    [
        ("a and b", "a or b", "swap:And->Or"),
        ("a and not b", "a and b", "drop_not:Ref"),
        ("a and b", "a and not b", "add_not:Ref"),
        ("(a or b) and c", "(a and b) and c", "swap:Or->And"),
        ("a", "a", "none"),
        ("a and b", "c", "other"),
    ],
)
def test_edit_signature(before, after, signature):
    assert edit_signature(parse_condition(before, NAMES), parse_condition(after, NAMES)) == signature


def _cases(tmp_path, split):
    from kestrixbench.variants import build
    from tests.bench.test_variants import make_root, split_manifest

    data = make_root(tmp_path / split)
    manifest = split_manifest()
    manifest["splits"] = {split: manifest["splits"]["development"], "reserve": []}
    return data, manifest, build


@pytest.mark.engine
def test_memory_reads_train_only_and_b1_repairs_by_analogy(tmp_path):
    from kestrixbench.evaluate import SYSTEMS, run_cases

    es = Elasticsearch(ES_URL)
    try:
        data, manifest, build = _cases(tmp_path, "train")
        build(data, manifest, {"per_rule": {}}, benign=set(), es=es, seed="s")
        cases = data / "benchmark/cases"
        memory = build_memory(cases)
        kinds = sorted({m.kind for m in memory})
        assert kinds == ["mapping", "rule"]  # healthy and missing-telemetry cases have nothing to learn
        assert any(m.signature == "CommandLine->process.command_line" for m in memory)

        # Same root's development variants, judged with a memory that only saw train.
        dev_data, dev_manifest, _ = _cases(tmp_path, "development")
        build(dev_data, dev_manifest, {"per_rule": {}}, benign=set(), es=es, seed="s")
        dev_cases = dev_data / "benchmark/cases"
        (dev_cases / "train").symlink_to(cases / "train")
        rows = {r["kind"]: r for r in run_cases(dev_cases, SYSTEMS["b1"](dev_cases), es)}
        assert rows["mapping"]["success"]
        assert rows["healthy"]["outcome"] == "unchanged"
        assert rows["missing_telemetry"]["outcome"] == "insufficient_evidence"
    finally:
        es.close()


def test_out_of_contract_proposals_are_skipped_not_fatal():
    from kestrix.detect.diagnose import Family, Hypothesis
    from kestrix.detect.fixtures import Dataset
    from kestrix.detect.mapping import FieldMapping
    from kestrix.detect.rule import parse_rule
    from kestrixbench.b1 import Repair, generator

    values = ", ".join(f"'v{i}.exe'" for i in range(9))
    rule = parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\n"
        f"detection:\n  sel: {{Image: [{values}]}}\n  condition: sel\n"
    )
    memory = [Repair(("field:Image", "family:logic"), "rule", "modifier:equals->endswith")]
    hyps = [Hypothesis(Family.LOGIC, ("malicious_missed_fields_present",))]
    propose = generator(memory)
    assert all(
        len(c.patch) == 1 for c in propose(rule, FieldMapping("m", {}), Dataset("d", (), "0" * 64), hyps, frozenset())
    )
