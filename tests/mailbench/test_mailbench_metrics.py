# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Baseline rescoring under feature sets, grouped-bootstrap rates, same-era strata, miss causes and the leakage report."""

import numpy as np
from mailbench_data import AUTH_FAIL, AUTH_MISSING, HIGH, LOW, MEDIUM, row

from kestrix.mail import analyze
from kestrixmailbench.features import feature_row
from kestrixmailbench.leakage import auc, era_table, flagged_pair, probe_separability
from kestrixmailbench.metrics import (
    ALL,
    CONTENT,
    CONTENT_STRICT,
    Frame,
    baseline_scoring,
    causes,
    default_strata,
    kept_findings,
    ratio_entry,
    restricted_verdict,
    strata_table,
    synthetic_table,
    table,
)
from kestrixmailbench.synthetic import generate


def test_rescoring_with_all_findings_matches_the_analyzer() -> None:
    for _family, _label, data in generate("seed", 3):
        stored = feature_row(data)
        report = analyze(data)
        verdict, score = restricted_verdict(kept_findings(stored, ALL))
        assert (verdict, score) == (report.verdict, report.heuristic_score)


def test_dropping_auth_findings_changes_the_verdict_rules() -> None:
    findings = [AUTH_FAIL, MEDIUM, AUTH_MISSING]
    stored = row(1, "phishing", "g", findings)
    assert restricted_verdict(kept_findings(stored, ALL))[0] == "malicious"  # DMARC fail plus another serious one
    assert restricted_verdict(kept_findings(stored, CONTENT))[0] == "suspicious"
    only_auth = row(2, "ham", "g", [AUTH_FAIL, AUTH_MISSING])
    assert restricted_verdict(kept_findings(only_auth, ALL))[0] == "suspicious"
    assert restricted_verdict(kept_findings(only_auth, CONTENT))[0] == "clean"


def test_content_strict_also_drops_header_era_ids() -> None:
    mailer = ["mail.sender.outdated_mailer", "low", "sender"]
    stored = row(1, "spam", "g", [mailer, LOW])
    assert [f[0] for f in kept_findings(stored, CONTENT)] == [mailer[0], LOW[0]]
    assert [f[0] for f in kept_findings(stored, CONTENT_STRICT)] == [LOW[0]]


def make_rows() -> list[dict[str, object]]:
    rows = []
    n = 0
    # phishing: groups p1 (2 of 3 flagged), p2 (1 of 1); spam: s1 (0 of 2); ham: h1 (1 of 4 flagged), e1 enron (0 of 5)
    for group, findings in (("p1", [HIGH]), ("p1", [MEDIUM]), ("p1", []), ("p2", [HIGH])):
        n += 1
        rows.append(row(n, "phishing", group, findings, year=2005))
    for _ in range(2):
        n += 1
        rows.append(row(n, "spam", "s1", [LOW], year=2003))
    for k in range(4):
        n += 1
        rows.append(row(n, "ham", "h1", [MEDIUM] if k == 0 else [], year=2003))
    for _ in range(5):
        n += 1
        rows.append(row(n, "ham", "e1", [], source="enron", year=2001))
    return rows


def test_table_rates_precision_and_verdict_shares() -> None:
    frame = Frame(make_rows())
    result = table(frame, baseline_scoring(frame, ALL), reps=50, seed=1, min_year_n=1)
    assert result["n"] == {
        "phishing": 4,
        "spam": 2,
        "all_positive": 6,
        "ham_spamassassin": 4,
        "ham_enron": 5,
        "ham_all": 9,
    }
    assert result["flagged_rate"]["phishing"]["rate"] == 0.75
    assert result["malicious_rate"]["phishing"]["rate"] == 0.5
    assert result["flagged_rate"]["spam"]["rate"] == 0.0
    assert result["flagged_rate"]["ham_spamassassin"]["rate"] == 0.25
    assert result["flagged_rate"]["ham_enron"]["rate"] == 0.0
    assert result["precision_flagged"]["phishing"]["rate"] == 0.75  # 3 true flags, 1 false flag: 3 / 4
    assert result["verdict_share"]["phishing"]["suspicious"]["k"] == 1
    assert result["by_source"]["nazario/phishing"]["flagged_rate"]["n"] == 4
    assert result["by_subset"]["nazario/x/phishing"]["flagged_rate"]["k"] == 3
    assert result["by_year"]["phishing"]["2005"]["flagged_rate"]["rate"] == 0.75


def test_interval_uses_whole_groups_and_is_reproducible() -> None:
    rows = [
        row(10 * g + k, "phishing", f"g{g}", [HIGH] if k < g else [], year=2005) for g in range(10) for k in range(10)
    ]
    frame = Frame(rows)
    flagged = np.array([bool(r["findings"]) for r in rows])
    num = np.bincount(frame.group, weights=flagged.astype(float), minlength=10)
    den = np.full(10, 10.0)
    first = ratio_entry(frame, num, den, 200, 3)
    assert first == ratio_entry(frame, num, den, 200, 3)
    assert first["rate"] == 0.45 and first["groups"] == 10 and first["n"] == 100 and first["k"] == 45
    low, high = first["ci95"]
    assert 0.0 <= low < 0.45 < high <= 0.9  # whole groups: only the ten group rates 0.0 to 0.9 can be drawn
    msg_low, msg_high = first["ci95_message"]
    assert 0.3 < msg_low < 0.45 < msg_high < 0.6
    assert ratio_entry(frame, np.zeros(10), np.zeros(10), 10, 0)["rate"] is None


def test_too_few_groups_get_no_group_interval_but_a_message_interval() -> None:
    frame = Frame(make_rows())
    num = np.array([2.0, 1.0, 0.0, 0.0, 0.0])
    den = np.array([3.0, 1.0, 0.0, 0.0, 0.0])
    entry = ratio_entry(frame, num, den, 200, 3)
    assert entry["rate"] == 0.75 and entry["groups"] == 2
    assert entry["ci95"] is None and entry["ci95_message"] is not None


def test_same_era_strata_pick_the_right_rows() -> None:
    rows = make_rows()
    rows.append(row(99, "spam", "s2", [LOW], year=2007))  # outside the SpamAssassin 2002-2005 window
    frame = Frame(rows)
    out = strata_table(frame, baseline_scoring(frame, ALL), default_strata(), reps=20, seed=1)
    same = out["same_corpus_spamassassin_2002_2005"]
    assert same["n_positive"] == 2 and same["n_ham"] == 4  # spam 2003 and ham 2003; Enron and 2007 excluded
    cross = out["ham_2002_2005_vs_positives_2005_2007"]
    assert cross["n_ham"] == 4 and cross["n_positive"] == 5  # phishing 2005 (4) and spam 2007 (1)
    assert cross["catch_rate_flagged"]["rate"] == 0.6


def test_causes_name_the_findings_behind_misses_and_false_alarms() -> None:
    frame = Frame(make_rows())
    out = causes(frame, ALL, baseline_scoring(frame, ALL))
    assert out["missed"]["phishing"]["missed"] == 1 and out["missed"]["phishing"]["with_no_finding"] == 1
    assert out["missed"]["spam"]["missed"] == 2
    assert out["missed"]["spam"]["ids_among_missed"][0] == {"id": LOW[0], "messages": 2, "share": 1.0}
    flagged = out["false_alarms"]["ham_spamassassin"]
    assert flagged["flagged"] == 1 and flagged["medium_or_high_ids_among_flagged"][0]["id"] == MEDIUM[0]
    assert out["false_alarms"]["ham_enron"]["flagged"] == 0


def test_synthetic_rows_are_kept_out_of_pooled_numbers() -> None:
    rows = make_rows() + [row(200 + k, "phishing", "fam", [HIGH], source="synthetic") for k in range(3)]
    frame = Frame(rows)
    scoring = baseline_scoring(frame, ALL)
    assert table(frame, scoring, reps=5)["n"]["phishing"] == 4
    assert synthetic_table(frame, scoring)["x"] == {"label": "phishing", "n": 3, "flagged": 3, "malicious": 3}


def test_auc_values() -> None:
    values = np.array([1.0, 2.0, 3.0, 4.0])
    assert auc(values, np.array([False, False, True, True])) == 1.0
    assert auc(values, np.array([True, True, False, False])) == 0.0
    assert auc(np.array([1.0, 1.0, 1.0, 1.0]), np.array([True, False, True, False])) == 0.5
    assert auc(values, np.array([True] * 4)) is None


def test_flagged_pair_needs_ratio_and_gap() -> None:
    assert flagged_pair(0.9, 0.1)
    assert not flagged_pair(0.5, 0.45)  # no ratio
    assert not flagged_pair(0.08, 0.02)  # ratio but no gap
    assert flagged_pair(0.4, 0.0)  # absent in one cell


def test_era_report_flags_ids_that_track_the_era() -> None:
    rows = []
    n = 0
    for _ in range(20):  # early phishing never has the id; late phishing always does
        n += 1
        rows.append(row(n, "phishing", "early", [LOW], year=2005, auth=0, received=5))
        n += 1
        rows.append(row(n, "phishing", "late", [LOW, AUTH_MISSING], year=2020, auth=1, received=1))
        n += 1
        rows.append(row(n, "ham", "ham", [], year=2003, auth=0, received=5))
    frame = Frame(rows)
    report = era_table(frame)
    assert report["era_sensitive_ids"] == [AUTH_MISSING[0]]
    by_id = {r["id"]: r for r in report["findings"]}
    assert by_id[LOW[0]]["era_sensitive"] is False
    assert by_id[AUTH_MISSING[0]]["frequency"]["phishing_late"] == 1.0
    assert report["probe_means"]["phishing_late"]["share_with_auth_header"] == 1.0
    probes = probe_separability(frame, default_strata())
    assert probes["all_dev"]["auth_header_present"] == 0.75  # positives: half have the header; ham never
    assert probes["all_dev"]["received_count"] is not None
