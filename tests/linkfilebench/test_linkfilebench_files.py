# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""File benchmark: content deduplication, the split, the synthetic cases and what the features store."""

import re
from pathlib import Path

import pytest
from linkfilebench_data import SENTINEL_BYTES, THREADS

from kestrixlinkfilebench.common import kind_layout, read_jsonl
from kestrixlinkfilebench.files import build_files, clean_ext, read_meta, run_file_shard, size_band
from kestrixlinkfilebench.metrics import FILE_CATEGORY, SECURITY, category
from kestrixlinkfilebench.split import check_disjoint, read_split, run_split
from kestrixlinkfilebench.synth import DEV_VARIANTS, FAMILIES, VARIANTS, generate


@pytest.fixture
def built(inputs: Path) -> Path:
    build_files(inputs / "raw", kind_layout(inputs, "file", 2), threads=list(THREADS))
    return inputs


def test_clean_ext_and_size_band() -> None:
    assert clean_ext("a/b/Report.PDF") == "pdf"
    assert clean_ext("noext") == "none" and clean_ext("dir.d/name") == "none"
    assert clean_ext("x.tar.gz") == "gz" and clean_ext("x.a b") == "other" and clean_ext("x." + "z" * 20) == "other"
    assert [size_band(n) for n in (0, 100, 5000, 70_000, 2_000_000, 20_000_000)] == [
        "0",
        "<4K",
        "<64K",
        "<1M",
        "<10M",
        ">=10M",
    ]


def test_build_keeps_each_content_once_and_adds_the_synthetic_cases(built: Path) -> None:
    layout = kind_layout(built, "file", 2)
    meta = read_meta(layout)
    gov = [m for m in meta if m["source"] == "govdocs1"]
    assert len(gov) == 29  # 2 x (12 text + 2 pdf) + one shared .doc kept once; directory entries skipped
    assert len(meta) == 29 + len(FAMILIES) * VARIANTS
    assert {m["group"] for m in gov} == {"govdocs1|001", "govdocs1|002"}
    assert len({m["id"] for m in meta}) == len(meta)
    report = (layout.reports / "build.json").read_text()
    assert '"govdocs1|duplicate_content": 1' in report


def test_build_refuses_a_thread_count_that_does_not_match_the_shards(inputs: Path) -> None:
    from kestrixlinkfilebench.common import LinkFileBenchError

    with pytest.raises(LinkFileBenchError, match="use --shards 2"):
        build_files(inputs / "raw", kind_layout(inputs, "file", 3), threads=list(THREADS))


def test_synthetic_groups_split_by_variant_and_govdocs_threads_stay_whole(built: Path) -> None:
    layout = kind_layout(built, "file", 2)
    meta = read_meta(layout)
    manifest = run_split(layout, meta, "file")
    split_of = read_split(layout)
    check_disjoint(meta, split_of)
    dev = manifest["splits"]["dev"]["by_source_label"]
    test = manifest["splits"]["test"]["by_source_label"]
    assert dev["synthetic/malicious"] == DEV_VARIANTS * sum(f.label == "malicious" for f in FAMILIES)
    assert test["synthetic/benign"] == (VARIANTS - DEV_VARIANTS) * sum(f.label == "benign" for f in FAMILIES)
    assert "govdocs1/benign" in dev


def test_features_cover_threads_and_synthetic_cases_without_names_or_content(built: Path) -> None:
    layout = kind_layout(built, "file", 2)
    meta_rows = read_meta(layout)
    run_split(layout, meta_rows, "file")
    meta = {m["id"]: m for m in meta_rows}
    split_of = read_split(layout)
    for shard in range(2):
        report = run_file_shard(
            layout, built / "raw", shard, meta, split_of, splits=("dev", "test"), threads=list(THREADS)
        )
        assert report["errors"] == {}
    rows = [r for shard in range(2) for side in ("dev", "test") for r in read_jsonl(layout.feature_file(shard, side))]
    assert len(rows) == len(meta_rows)
    text = "".join(layout.feature_file(s, side).read_text() for s in range(2) for side in ("dev", "test"))
    assert SENTINEL_BYTES.decode() not in text and "readme" not in text
    assert re.search(r"\d{3}\.pdf|\.docm|invoice_", text) is None  # no file names
    gov_pe = [r for r in rows if r["source"] == "govdocs1" and r["type"] == "pe"]
    assert gov_pe and all(("extension_mismatch", "high") in map(tuple, r["findings"]) for r in gov_pe)
    assert {r["source"] for r in rows} == {"govdocs1", "synthetic"}
    assert oct(layout.feature_file(0, "dev").stat().st_mode & 0o777) == "0o600"


def test_a_file_over_the_analyzer_limit_is_counted_not_analyzed(built: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import kestrixlinkfilebench.files as module

    monkeypatch.setattr(module, "MAX_FILE_BYTES", 40)
    layout = kind_layout(built, "file", 2)
    report = build_files(built / "raw", layout, threads=list(THREADS))
    assert report["dropped"]["govdocs1|input_too_large"] > 0


def test_every_file_finding_id_in_the_source_has_a_category() -> None:
    source = Path(__file__).resolve().parents[2] / "src" / "kestrix" / "forensics"
    ids = set()
    for name in ("analysis.py", "exif.py"):
        ids |= set(re.findall(r'(?:_finding|Finding)\(\s*(?:id=)?"([a-z_]+)"', (source / name).read_text()))
    assert len(ids) >= 10
    assert ids <= set(FILE_CATEGORY), f"uncategorized: {sorted(ids - set(FILE_CATEGORY))}"
    assert set(FILE_CATEGORY) <= ids | {"gps_location", "identifying_metadata"}
    assert category("some_new_id") == SECURITY  # an unlisted id counts as a security finding


def test_synthetic_cases_are_deterministic_and_named_like_their_family() -> None:
    first, second = generate(), generate()
    assert [(c.name, c.data) for c in first] == [(c.name, c.data) for c in second]
    assert len({c.id for c in first}) == len(first)
    assert {c.side for c in first} == {"dev", "test"}
    assert all(c.group.endswith(("|dev", "|test")) for c in first)


def test_every_synthetic_family_triggers_what_it_was_built_for_and_controls_stay_quiet() -> None:
    import io

    from kestrix.forensics.analysis import analyze_file
    from kestrixlinkfilebench.synth import FAMILY_BY_NAME

    for case in generate(variants=5):
        report = analyze_file(io.BytesIO(case.data), case.name)
        fired = {f.id for f in report.findings}
        alarm = max(
            (f.severity for f in report.findings if category(f.id) == SECURITY and f.severity != "info"), default="none"
        )
        if case.family == "script_attachment" and case.name.endswith(".js"):
            continue  # JavaScript is only a low signal by design
        assert set(case.expected) <= fired, (case.family, case.name, sorted(fired))
        if case.label == "benign":
            assert alarm == "none", (case.family, sorted(fired))
    assert FAMILY_BY_NAME["html_obfuscated"].expected == ()
