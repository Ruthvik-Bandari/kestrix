# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Accuracy benchmark for the ``kestrix.forensics`` URL checker and file checker.

Research tooling, not part of the published wheel. It follows ``kestrixmailbench`` (same layout, split
claim, grouped bootstrap) and imports its shared helpers. URLs are text only and are never fetched;
files are read as bytes and never executed. Raw data stays on the cluster; reports hold counts, rates,
intervals and finding ids only. See ``docs/research/linkfile-benchmark.md``.
"""
