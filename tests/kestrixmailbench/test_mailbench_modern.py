# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Modern normal-mail measurement: split by list, build, header probes, held-out lock, report privacy."""

import json
from pathlib import Path
from typing import Any

import pytest
from mailbench_data import SENTINEL, eml, mbox

from kestrixmailbench.common import Layout, MailBenchError
from kestrixmailbench.modern_acquire import ASF, GNU, acquire, feeds
from kestrixmailbench.modern_report import full_report, heldout, synthetic_report
from kestrixmailbench.modern_run import (
    analyze_shard,
    assign_lists,
    build,
    header_probes,
    read_split_features,
)
from kestrixmailbench.modern_synth import FAMILIES, generate

LIST_HEADERS = (
    "List-Id: <dev.proj.example>\nList-Unsubscribe: <mailto:dev-unsubscribe@proj.example>\nReply-To: dev@proj.example\n"
)


def test_feeds_cover_both_sources_and_five_years() -> None:
    all_feeds = feeds()
    assert {f.source for f in all_feeds} == {ASF, GNU}
    assert {f.year for f in all_feeds} == {2022, 2023, 2024, 2025, 2026}
    assert len({f.filename for f in all_feeds if f.source == ASF}) == len([f for f in all_feeds if f.source == ASF])
    assert all(f.url.startswith("https://") for f in all_feeds)


def test_assign_lists_holds_out_lists_per_source_deterministically() -> None:
    lists = {"asf": [f"l{i}" for i in range(8)], "gnu": [f"g{i}" for i in range(7)]}
    first = assign_lists(lists)
    assert first == assign_lists(lists)
    assert sum(1 for k, v in first.items() if k.startswith("asf|") and v == "heldout") == 3
    assert sum(1 for k, v in first.items() if k.startswith("gnu|") and v == "heldout") == 2


def test_acquire_records_missing_and_failed_months(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    calls: list[str] = []

    def opener(request: Any) -> Any:
        calls.append(request.full_url)
        raise OSError("boom")

    from kestrixmailbench import modern_acquire

    original = modern_acquire.download

    def fake_download(url: str, dest: Path, op: Any) -> dict[str, Any]:
        if "kafka" in url:
            raise MailBenchError(f"{dest.name}: download failed: HTTP Error 404")
        raise MailBenchError(f"{dest.name}: download failed: timed out")

    modern_acquire.download = fake_download  # type: ignore[assignment]
    try:
        out = acquire(layout, only=ASF, opener=opener, sleep=lambda _s: None)
    finally:
        modern_acquire.download = original
    assert out["failed"]
    assert all("kafka" not in name for name in out["failed"])
    assert any(f["size"] == 0 for f in out["files"])  # the 404 months are recorded as empty


def _write_months(layout: Layout) -> None:
    for source, names in (("asf", ["dev-a", "dev-b", "dev-c", "dev-d"]), ("gnu", ["g-a", "g-b", "g-c"])):
        folder = layout.raw / "modern" / source
        folder.mkdir(parents=True)
        for k, name in enumerate(names):
            msgs = [
                eml(1000 * (k + 10 * (source == "gnu")) + n, extra=LIST_HEADERS, date="Mon, 04 Mar 2024 10:00:00 +0000")
                for n in range(6)
            ]
            (folder / f"{name}_2024-03.mbox").write_bytes(mbox(msgs))


def test_build_splits_by_list_and_adds_synthetic(tmp_path: Path) -> None:
    layout = Layout(tmp_path, shards=2)
    _write_months(layout)
    report = build(layout)
    meta = [json.loads(line) for line in layout.meta.read_text().splitlines()]
    real = [m for m in meta if m["source"] != "synthetic_modern"]
    assert len(real) == 7 * 6
    owner: dict[str, set[str]] = {}
    for m in real:
        owner.setdefault(f"{m['source']}|{m['subset']}", set()).add(m["split"])
    assert all(len(v) == 1 for v in owner.values())  # a list is wholly dev or wholly held out
    assert {m["split"] for m in real} == {"dev", "heldout"}
    assert report["splits"]["synthetic"]["messages"] == len(FAMILIES) * 15
    assert SENTINEL not in json.dumps(report)


def test_features_refuse_heldout_and_probes_hold_no_values(tmp_path: Path) -> None:
    layout = Layout(tmp_path, shards=2)
    _write_months(layout)
    build(layout)
    for shard in range(2):
        analyze_shard(layout, shard, ("dev", "synthetic"))
    dev = read_split_features(layout, "dev")
    assert dev and all(r["split"] == "dev" for r in dev)
    assert SENTINEL not in json.dumps(dev)
    assert not (layout.features / "modern-heldout-shard-00.jsonl").exists()
    probes = header_probes(
        eml(1, extra=LIST_HEADERS + "Authentication-Results: mx.example; dkim=pass; spf=fail; dmarc=pass\n")
    )
    assert probes["list_id"] and probes["reply_to"]
    assert probes["ar"] == {"authserv": "mx.example", "dkim": ["pass"], "spf": ["fail"], "dmarc": ["pass"], "arc": []}


def test_heldout_runs_once(tmp_path: Path) -> None:
    layout = Layout(tmp_path, shards=2)
    _write_months(layout)
    build(layout)
    heldout(layout, 20)
    report = json.loads((layout.reports / "modern-heldout.json").read_text())
    assert report["split"] == "heldout" and report["all_findings"]["n"] > 0
    assert SENTINEL not in json.dumps(report)
    with pytest.raises(Exception, match="already ran"):
        heldout(layout, 20)


def test_report_sections_and_synthetic_cohort(tmp_path: Path) -> None:
    layout = Layout(tmp_path, shards=2)
    _write_months(layout)
    build(layout)
    for shard in range(2):
        analyze_shard(layout, shard, ("dev", "synthetic"))
    body = full_report(read_split_features(layout, "dev"), "dev", 20)
    assert set(body) >= {"all_findings", "causes", "auth", "reply_to", "content_only"}
    assert body["reply_to"]["with_list_id"] == body["reply_to"]["messages"]
    synth = synthetic_report(read_split_features(layout, "synthetic"))
    assert set(synth["families"]) == set(FAMILIES)


def test_synthetic_modern_is_reproducible_and_clean() -> None:
    from kestrix.mail.analyze import analyze

    first = generate("s", 2)
    assert first == generate("s", 2) and len({d for _, d in first}) == len(first)
    # Clean when the synthetic provider's authserv-id is trusted. Without it, the DMARC pass of the security
    # alert is unverified and no longer lowers its credential request, so that family alone is suspicious.
    assert all(analyze(d, trusted_authserv_ids=frozenset({"mx.example.net"})).verdict == "clean" for _, d in first)
    flagged = {family for family, d in first if analyze(d).verdict != "clean"}
    assert flagged == {"security_alert"}


def _html(body: str, extra: str = "") -> bytes:
    return (
        "From: Alice <alice@sender.example>\nTo: bob@example.org\nSubject: hello there\n"
        "Date: Mon, 04 Mar 2024 10:00:00 +0000\nMessage-ID: <1@sender.example>\n"
        f"Content-Type: text/html; charset=utf-8\n{extra}\n{body}\n"
    ).encode()


def test_variants_match_the_shipped_rules_and_restore_the_module() -> None:
    """P1, P3 and P6 are now in ``kestrix.mail``: the bench variants agree with the unpatched analyzer."""
    from kestrix.mail import analyze
    from kestrixmailbench import modern_proposals as mp

    wrapped = _html(
        '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdocs.partner.com%2Fx">'
        "docs.partner.com</a>"
    )
    local = _html('<a href="http://192.168.1.5/status">status</a>')
    public = _html('<a href="http://8.8.8.8/status">status</a>')
    lst = _html("hello", "List-Id: <dev.proj.example>\nReply-To: someone@gmail.com\n")
    assert analyze(wrapped).verdict == "insufficient_evidence"
    assert analyze(local).verdict != "suspicious"
    assert analyze(public).verdict == "suspicious"
    assert analyze(lst).verdict != "suspicious"
    for raw, name in [
        (wrapped, "p1_unwrap_rewriters"),
        (local, "p3_private_ip"),
        (public, "p3_private_ip"),
        (lst, "p6_list_freemail_reply"),
        (wrapped, "base"),
    ]:
        assert mp.analyze_variant(raw, name) == analyze(raw).verdict
    assert mp.analyze_module.analyze_links.__module__ == "kestrix.mail.analyzers"  # patches were removed


def test_diag_shapes_hold_no_private_values() -> None:
    from kestrixmailbench.modern_proposals import shape

    out = shape("text shows secret.person.example; link goes to evil@corp.example/path?token=abc and github.com/x")
    assert "secret" not in out and "person" not in out and "corp" not in out and "token" not in out
    assert "github.com" in out


FORGED_LURE = (
    b"Authentication-Results: attacker.invalid; dmarc=pass header.from=sender.example\n"
    b"From: Alice <alice@sender.example>\nTo: bob@example.org\nSubject: hello there\n"
    b"Date: Mon, 04 Mar 2024 10:00:00 +0000\nMessage-ID: <1@sender.example>\n\n"
    b"We noticed an unusual sign-in. Verify your account.\n"
)


def test_before_auth_fix_variant_restores_the_old_rule_and_the_module() -> None:
    """The bench variant reproduces the pre-fix rule (an unverified topmost pass lowered the credential request)."""
    from kestrix.mail import analyze
    from kestrix.mail.analyzers import dmarc_passed
    from kestrixmailbench import modern_proposals as mp

    assert analyze(FORGED_LURE).verdict == "suspicious"
    assert mp.analyze_variant(FORGED_LURE, "base") == "suspicious"
    assert mp.analyze_variant(FORGED_LURE, "before_auth_fix") == "clean"
    assert mp.analyze_module.dmarc_passed is dmarc_passed  # the patch was removed
    assert mp.variant_names("before_auth_fix") == ("base", "before_auth_fix")
    assert mp.variant_names(None) == tuple(mp.VARIANTS)
    with pytest.raises(MailBenchError):
        mp.variant_names("nope")


def test_variants_report_counts_changed_verdicts(tmp_path: Path) -> None:
    from kestrixmailbench.common import write_jsonl
    from kestrixmailbench.modern_proposals import variants_report
    from kestrixmailbench.modern_report import variants_tag

    layout = Layout(tmp_path, shards=2)
    layout.features.mkdir(parents=True)

    def row(i: int, source: str, label: str, base: str, before: str) -> dict[str, object]:
        return {"id": f"m{i}", "source": source, "subset": "s", "label": label, "year": 2024, "group": f"g{i % 3}",
                "origin": "old", "v": {"base": base, "before_auth_fix": before}}  # fmt: skip

    rows = [
        row(0, "nazario", "phishing", "suspicious", "clean"),
        row(1, "nazario", "phishing", "malicious", "malicious"),
    ]
    write_jsonl(layout.features / "modern-variants-auth-shard-00.jsonl", rows)
    write_jsonl(layout.features / "modern-variants-auth-shard-01.jsonl", [row(2, "enron", "ham", "clean", "clean")])
    out = variants_report(layout, 20, variants_tag("auth"))
    before = out["variants"]["before_auth_fix"]
    assert before["old_phishing"]["flagged"]["k"] == 1
    assert out["variants"]["base"]["old_phishing"]["flagged"]["k"] == 2
    assert before["changed_vs_base"]["old_phishing"] == {
        "messages": 1,
        "transitions_base_to_variant": {"suspicious->clean": 1},
    }
    assert before["changed_vs_base"]["old_enron_ham"]["messages"] == 0
    with pytest.raises(MailBenchError):
        variants_tag("Bad/tag")
