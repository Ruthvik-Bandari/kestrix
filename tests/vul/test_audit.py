# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import csv
import io
import json
from pathlib import Path

import pytest

from kestrixvul.audit import (
    CSV_FIELDS,
    AuditError,
    aggregate,
    allocate,
    cohen_kappa,
    combine,
    draw,
    import_verdicts,
    packet_sha256,
    wilson,
)


def _rec(i: int, language: str, rule: str, split: str = "train") -> dict:
    return {"id": f"{language}-{rule}-{i}", "language": language, "label_rule": rule, "split": split, "source": "ghsa"}


def test_allocation_takes_a_floor_per_stratum_then_proportional_top_up():
    quota = allocate({"a": 400, "b": 100, "c": 10}, per_stratum=25, target=100)
    assert quota["c"] == 10 and sum(quota.values()) == 100
    assert quota["a"] > quota["b"] >= 25


def test_draw_is_seeded_and_never_samples_test_records():
    records = [_rec(i, "python", "onefunc") for i in range(100)] + [
        _rec(i, "python", "nvd_name", "test") for i in range(50)
    ]
    first, population = draw(records)
    assert first == draw(records)[0]
    assert population == {"python/onefunc": 100}
    assert all(r["split"] != "test" for r in first)
    assert first != draw(records, seed="other")[0]


def test_wilson_and_kappa():
    assert wilson(0, 0) is None
    low, high = wilson(18, 20) or (0, 0)
    assert 0.68 < low < 0.70 and 0.97 < high < 0.98
    assert cohen_kappa([("vulnerable", "vulnerable"), ("not_vulnerable", "not_vulnerable")]) == 1.0
    assert cohen_kappa([("vulnerable", "not_vulnerable"), ("not_vulnerable", "vulnerable")]) == -1.0


def _packets() -> list[dict]:
    out = []
    for i in range(10):
        p = {"id": f"p{i}", "stratum": "python/nvd_name" if i < 6 else "python/onefunc", "source": "cvefixes"}
        p["packet_sha256"] = packet_sha256(p)
        out.append(p)
    return out


def _review(pid: str, verdict: str) -> dict:
    return {"id": pid, "verdict": verdict, "patch": "fixes", "reason": "one line"}


def test_combine_uses_adjudication_only_on_disagreement():
    packets = _packets()[:2]
    a = [_review("p0", "vulnerable"), _review("p1", "vulnerable")]
    b = [_review("p0", "vulnerable"), _review("p1", "not_vulnerable")]
    with pytest.raises(AuditError):
        combine(packets, a, b, [])
    rows = combine(packets, a, b, [_review("p1", "not_vulnerable")])
    assert [(r["final"], r["final_by"]) for r in rows] == [
        ("vulnerable", "ai-consensus"),
        ("not_vulnerable", "ai-adjudicated"),
    ]
    with pytest.raises(AuditError):
        combine(packets, [*a, {"id": "p0", "verdict": "maybe", "reason": "x"}], b, [])


def test_aggregate_flags_strata_below_the_threshold():
    packets = _packets()
    verdicts = [
        {"id": p["id"], "verdict_a": v, "verdict_b": v, "final": v, "final_by": "ai-consensus", "patch_final": "fixes"}
        for p, v in zip(
            packets,
            ["vulnerable", "not_vulnerable", "not_vulnerable", "vulnerable", "unclear", "vulnerable"]
            + ["vulnerable"] * 4,
            strict=True,
        )
    ]
    report = aggregate(packets, verdicts, {"python/nvd_name": 300, "python/onefunc": 100})
    assert report["per_stratum"]["python/nvd_name"]["label_accuracy"] == 0.5
    assert report["per_stratum"]["python/onefunc"]["label_accuracy"] == 1.0
    # onefunc has n=4 < 5 and is kept anyway; the same records also form the source group
    assert report["filter"]["dropped_strata"] == ["python/nvd_name", "source:cvefixes/nvd_name"]
    assert report["overall_weighted_by_population"] == 0.625
    assert report["agreement"]["cohen_kappa"] == 1.0
    assert "reason" not in json.dumps(report)


def test_import_checks_packet_hashes_and_consistency(tmp_path: Path):
    packets = _packets()
    (tmp_path / "audit").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "work").mkdir()
    (tmp_path / "audit" / "packets.jsonl").write_text("".join(json.dumps(p) + "\n" for p in packets))
    (tmp_path / "reports" / "audit-sample.json").write_text(json.dumps({"population_by_stratum": {}}))

    def table(rows: list[dict]) -> Path:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        path = tmp_path / "verdicts.csv"
        path.write_text(buf.getvalue())
        return path

    good = [
        {"id": p["id"], "packet_sha256": p["packet_sha256"], "verdict_a": "vulnerable", "verdict_b": "vulnerable",
         "final": "vulnerable", "final_by": "ai-consensus", "patch_final": "fixes"}
        for p in packets
    ]  # fmt: skip
    report = import_verdicts(tmp_path, table(good))
    assert report["audited"] == 10
    assert (tmp_path / "work" / "audit_verdicts.jsonl").stat().st_mode & 0o777 == 0o600
    with pytest.raises(AuditError):
        import_verdicts(tmp_path, table([dict(good[0], packet_sha256="0" * 64), *good[1:]]))
    with pytest.raises(AuditError):
        import_verdicts(
            tmp_path, table([dict(good[0], verdict_b="unclear"), *good[1:]])
        )  # disagreement marked consensus
    with pytest.raises(AuditError):
        import_verdicts(tmp_path, table(good[1:]))
