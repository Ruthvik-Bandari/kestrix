# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Metrics on hand-built feature rows: counts, rates, categories, the matched subset and the collection flag."""

from typing import Any

import numpy as np

from kestrixlinkfilebench.leakage import cell_of, finding_gaps, matched_ids, probe_separability
from kestrixlinkfilebench.metrics import (
    file_alarm,
    file_causes,
    file_table,
    link_causes,
    link_rank,
    link_table,
    shape_table,
    synthetic_table,
)
from kestrixmailbench.metrics import Frame


def link(
    n: int, label: str, level: str, *, source: str = "phiusiil", findings: list[list[str]] | None = None, **shape: Any
) -> dict[str, Any]:
    return {
        "id": f"{source}-{label}-{n}",
        "source": source,
        "subset": label,
        "label": label,
        "year": None,
        "group": f"g{n}",
        "level": level,
        "score": {"none": 0, "low": 10, "medium": 35, "high": 70}[level],
        "findings": findings or [],
        "len": shape.get("len", 30),
        "path": shape.get("path", 0),
        "query": shape.get("query", 0),
        "depth": 0,
        "dots": 1,
        "hyph": 0,
        "digits": 0,
        "https": shape.get("https", 1),
        "tld": shape.get("tld", "com"),
    }


def test_link_table_counts_catch_false_alarms_and_precision() -> None:
    rows = [link(i, "phishing", "high" if i < 3 else "medium" if i < 6 else "none") for i in range(10)]
    rows += [link(i, "benign", "medium" if i == 0 else "none") for i in range(10)]
    rows += [link(i, "benign", "none", source="majestic") for i in range(5)]
    frame = Frame(rows)
    table = link_table(frame, link_rank(frame), reps=20)
    medium = table["levels"]["medium_or_higher"]
    assert (medium["phishing_caught"]["k"], medium["phishing_caught"]["n"]) == (6, 10)
    assert medium["false_alarm_benign_phiusiil"]["rate"] == 0.1 and medium["false_alarm_benign_majestic"]["rate"] == 0.0
    assert medium["false_alarm_benign_all"]["k"] == 1 and medium["false_alarm_benign_all"]["n"] == 15
    assert round(medium["precision_vs_benign_all"]["rate"], 4) == round(6 / 7, 4)
    assert table["levels"]["high"]["phishing_caught"]["k"] == 3
    assert table["n"] == {"phishing": 10, "benign_phiusiil": 10, "benign_majestic": 5, "benign_all": 15}


def test_link_causes_and_shapes() -> None:
    rows = [link(i, "phishing", "none", findings=[["long_url", "low"]]) for i in range(4)]
    rows += [link(4, "phishing", "high", findings=[["ip_address_host", "high"]], https=0, path=1)]
    rows += [link(5, "phishing", "none")]
    rows += [link(i, "benign", "medium", findings=[["brand_in_domain", "medium"]]) for i in range(3)]
    rows += [link(i, "benign", "none") for i in range(3, 6)]
    frame = Frame(rows)
    causes = link_causes(frame, link_rank(frame))
    missed = causes["missed"]["below_medium"]
    assert missed["missed"] == 5 and missed["with_no_finding"] == 1
    assert missed["ids_among_missed"][0] == {"id": "long_url", "items": 4, "share": 0.8}
    flagged = causes["false_alarms"]["benign_phiusiil"]["medium_or_higher"]
    assert flagged["flagged"] == 3 and flagged["ids_among_flagged"][0]["id"] == "brand_in_domain"
    shapes = shape_table(frame, link_rank(frame), reps=5)
    assert shapes["phishing/http/path_or_query"]["n"] == 1 and shapes["benign_phiusiil/https/bare"]["n"] == 6


def collection_rows() -> list[dict[str, Any]]:
    """Phishing is half http, benign is all https (a collection difference); ``ip_address_host`` is a real signal."""
    rows = []
    for i in range(40):
        http = i % 2 == 0
        findings = [["not_https", "low"]] if http else []
        if i % 4 == 1:
            findings = [["ip_address_host", "high"]]
        rows.append(link(i, "phishing", "low", findings=findings, https=0 if http else 1))
    rows += [link(i, "benign", "none") for i in range(40)]
    return rows


def test_matched_subset_has_equal_counts_per_cell_and_is_deterministic() -> None:
    rows = [*collection_rows(), link(99, "benign", "none", source="majestic")]
    ids = matched_ids(rows)
    assert ids == matched_ids(list(reversed(rows)))
    chosen = [r for r in rows if r["id"] in ids]
    assert all(r["source"] == "phiusiil" for r in chosen)
    cells: dict[tuple[int, int, int, int], dict[str, int]] = {}
    for r in chosen:
        cells.setdefault(cell_of(r), {"phishing": 0, "benign": 0})[r["label"]] += 1
    assert all(c["phishing"] == c["benign"] for c in cells.values())
    assert set(cells) == {(1, 0, 0, 2)}  # only https host roots of one length band exist in both classes
    assert sum(c["phishing"] for c in cells.values()) == 20


def test_collection_driven_findings_are_flagged_and_real_signals_are_not() -> None:
    rows = collection_rows()
    ids = matched_ids(rows)
    gaps = finding_gaps(Frame(rows), Frame([r for r in rows if r["id"] in ids]))
    assert gaps["not_https"]["collection_driven"] is True and gaps["not_https"]["gap_matched"] == 0.0
    assert gaps["ip_address_host"]["collection_driven"] is False
    assert gaps["ip_address_host"]["gap_matched"] > 0.2


def test_probe_separability_sees_the_scheme_difference() -> None:
    probes = probe_separability(Frame(collection_rows()))
    assert probes["https"] < 0.5 and probes["length"] == 0.5  # phishing is less often https; equal lengths say nothing
    assert probes["n_phishing"] == 40 and probes["n_benign"] == 40


def file_row(
    n: int, source: str, findings: list[list[str]], *, type_: str = "pdf", ext: str = "pdf", group: str = "t1"
) -> dict[str, Any]:
    return {
        "id": f"{source}-{n}",
        "source": source,
        "subset": group if source == "govdocs1" else f"fam{n % 2}",
        "label": "benign",
        "year": None,
        "group": f"{source}|{group}",
        "type": type_,
        "ext": ext,
        "findings": findings,
        "exif": "no_exif",
    }


def test_file_alarm_counts_security_findings_only() -> None:
    rows = [
        file_row(0, "govdocs1", []),
        file_row(1, "govdocs1", [["gps_location", "high"]]),
        file_row(2, "govdocs1", [["executable_file", "info"], ["extension_mismatch", "medium"]]),
        file_row(3, "govdocs1", [["brand_new_unlisted_id", "high"]]),
    ]
    frame = Frame(rows)
    assert file_alarm(frame).tolist() == [0, 0, 2, 3]
    assert file_alarm(frame, ("security", "privacy")).tolist() == [0, 3, 2, 3]


def test_file_table_rates_by_type_and_finding_id() -> None:
    rows = [file_row(i, "govdocs1", [], group=f"t{i % 4}") for i in range(60)]
    rows += [
        file_row(100 + i, "govdocs1", [["extension_mismatch", "medium"]], type_="text", ext="doc", group=f"t{i % 4}")
        for i in range(10)
    ]
    frame = Frame(rows)
    table = file_table(frame, reps=10, min_n=5)
    assert table["n"] == 70
    assert table["false_alarm_security"]["medium_or_higher"]["k"] == 10
    assert (
        table["by_type"]["text"]["medium_or_higher"]["rate"] == 1.0
        and table["by_type"]["pdf"]["medium_or_higher"]["k"] == 0
    )
    assert table["by_finding_id"]["extension_mismatch"]["category"] == "security"
    causes = file_causes(frame)
    assert causes["medium_or_higher"]["flagged"] == 10
    assert causes["medium_or_higher"]["id_type_extension"][0]["id"] == "extension_mismatch | text | .doc"
    assert np.isclose(causes["medium_or_higher"]["false_alarm_rate"], 10 / 70, atol=1e-4)


def test_synthetic_table_reports_each_family_and_the_summary() -> None:
    rows = [
        {
            **file_row(i, "synthetic", [["double_extension", "high"]] if i < 3 else []),
            "subset": "bad",
            "label": "malicious",
        }
        for i in range(4)
    ]
    rows += [{**file_row(10 + i, "synthetic", []), "subset": "good", "label": "benign"} for i in range(2)]
    table = synthetic_table(Frame(rows))
    assert table["families"]["bad"]["alarm_high"] == 3 and table["families"]["bad"]["n"] == 4
    assert table["families"]["bad"]["security_ids_fired"] == {"double_extension": 3}
    assert table["summary"]["malicious_caught_medium_or_higher"] == 3
    assert table["summary"]["malicious_families_fully_caught_medium_or_higher"] == 0
    assert table["summary"]["benign_control_alarm_low_or_higher"] == 0
