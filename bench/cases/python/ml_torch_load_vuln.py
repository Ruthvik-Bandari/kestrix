# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-502): Loads a user-uploaded checkpoint with torch.load defaults."""

import torch


def load_checkpoint(path: str) -> dict:
    """Load a fine-tuned checkpoint the user uploaded through the dashboard."""
    state = torch.load(path, map_location="cpu")
    return state["model"]
