# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-502): Downloads weights and loads them with safetensors."""

import tempfile

import httpx
from safetensors.torch import load_file


def fetch_weights(url: str):
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as fh:
        fh.write(httpx.get(url, timeout=30).content)
    return load_file(fh.name)
