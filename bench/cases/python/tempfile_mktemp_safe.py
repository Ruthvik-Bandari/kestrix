# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-377): Writes an export through NamedTemporaryFile."""

import tempfile


def export_csv(rows: list[str]) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(rows))
    return fh.name
