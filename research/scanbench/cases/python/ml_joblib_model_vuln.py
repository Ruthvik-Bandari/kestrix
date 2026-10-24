# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-502): Downloads a model file and loads it with joblib."""

import tempfile

import httpx
import joblib


def fetch_model(url: str):
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as fh:
        fh.write(httpx.get(url, timeout=30).content)
    return joblib.load(fh.name)
