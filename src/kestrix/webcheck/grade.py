"""Deterministic grading rubric.

Start at 100 and subtract 25 per high, 10 per medium and 4 per low finding (info costs
nothing), with a floor of 0. Grades: A >= 90, B >= 80, C >= 70, D >= 60, otherwise F.
The grade is forced to F when the site is not served over HTTPS or the TLS check failed,
because every other protection depends on an intact connection.
"""

from __future__ import annotations

from typing import Literal

from .models import Finding, TlsInfo

PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0}
BANDS: tuple[tuple[int, Literal["A", "B", "C", "D"]], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


def grade(findings: list[Finding], final_scheme: str, tls: TlsInfo) -> tuple[Literal["A", "B", "C", "D", "F"], int]:
    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    if final_scheme != "https" or tls.status != "ok":
        return "F", score
    return next((letter for floor, letter in BANDS if score >= floor), "F"), score
