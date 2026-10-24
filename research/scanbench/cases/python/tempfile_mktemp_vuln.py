# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-377): Writes an export to a name from tempfile.mktemp."""

import tempfile


def export_csv(rows: list[str]) -> str:
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rows))
    return path
