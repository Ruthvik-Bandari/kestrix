# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""OWASP Benchmark scoring, written from the BenchmarkUtils method (no code copied).

A test case is *flagged* by a tool when at least one of the tool's findings in that test case's file matches the
case: by category (primary mode) or by an equal CWE (strict mode). Then, per category:

- TP: a real vulnerability that is flagged; FN: a real vulnerability that is not;
- FP: a safe case that is flagged; TN: a safe case that is not;
- TPR = TP / (TP + FN), FPR = FP / (FP + TN), each 0 when its denominator is 0;
- score (Youden index) = TPR - FPR.

The overall TPR and FPR are the unweighted means over categories and the overall score is their difference, as in
BenchmarkUtils; overall precision is pooled, TP / (TP + FP) over all cases.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

Mode = Literal["category", "strict"]
_ROW = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+),(?P<category>[a-z]+),(?P<real>true|false),(?P<cwe>\d+)$")


@dataclass(frozen=True)
class Case:
    name: str
    category: str
    real: bool
    cwe: int


@dataclass(frozen=True)
class Finding:
    """One tool finding reduced to what scoring needs: where, which rule, which CWEs and categories."""

    path: str  # posix path relative to the scanned root
    rule: str
    cwes: frozenset[int]
    categories: frozenset[str]


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def tpr(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def score(self) -> float:
        return self.tpr - self.fpr

    def add(self, real: bool, flagged: bool) -> Counts:
        if real:
            return Counts(self.tp + flagged, self.fp, self.tn, self.fn + (not flagged))
        return Counts(self.tp, self.fp + flagged, self.tn + (not flagged), self.fn)


@dataclass(frozen=True)
class Scorecard:
    categories: dict[str, Counts]
    flagged: frozenset[str]

    @property
    def tpr(self) -> float:
        return sum(c.tpr for c in self.categories.values()) / len(self.categories) if self.categories else 0.0

    @property
    def fpr(self) -> float:
        return sum(c.fpr for c in self.categories.values()) / len(self.categories) if self.categories else 0.0

    @property
    def score(self) -> float:
        return self.tpr - self.fpr

    @property
    def precision(self) -> float:
        tp = sum(c.tp for c in self.categories.values())
        fp = sum(c.fp for c in self.categories.values())
        return tp / (tp + fp) if tp + fp else 0.0


class ExpectedResultsError(ValueError):
    pass


def parse_expected(text: str) -> list[Case]:
    """Read an expected-results CSV: ``# comment`` lines, then ``name,category,true|false,cwe`` rows."""
    cases: list[Case] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ROW.match(line)
        if match is None:
            raise ExpectedResultsError(f"line {number}: expected 'name,category,true|false,cwe'")
        name = match["name"]
        if name in seen:
            raise ExpectedResultsError(f"line {number}: duplicate test case {name}")
        seen.add(name)
        cases.append(Case(name, match["category"], match["real"] == "true", int(match["cwe"])))
    if not cases:
        raise ExpectedResultsError("no test cases")
    return cases


def case_of(path: str, names: Mapping[str, Case]) -> Case | None:
    """The test case a finding's file belongs to: the first path component (or file stem) that names a case."""
    parts = PurePosixPath(path).parts
    for i, part in enumerate(parts):
        stem = PurePosixPath(part).stem if i == len(parts) - 1 else part
        if part in names:
            return names[part]
        if stem in names:
            return names[stem]
    return None


def matches(case: Case, finding: Finding, mode: Mode) -> bool:
    return case.cwe in finding.cwes if mode == "strict" else case.category in finding.categories


def score(cases: Sequence[Case], findings: Iterable[Finding], mode: Mode) -> Scorecard:
    names = {case.name: case for case in cases}
    flagged: set[str] = set()
    for finding in findings:
        case = case_of(finding.path, names)
        if case is not None and matches(case, finding, mode):
            flagged.add(case.name)
    per_category: dict[str, Counts] = {}
    for case in cases:
        per_category[case.category] = per_category.get(case.category, Counts()).add(case.real, case.name in flagged)
    return Scorecard(dict(sorted(per_category.items())), frozenset(flagged))
