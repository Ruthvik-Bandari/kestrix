# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-502): Loads a checkpoint with weights_only=True."""

import torch


def load_checkpoint(path: str) -> dict:
    """Load a fine-tuned checkpoint the user uploaded through the dashboard."""
    state = torch.load(path, map_location="cpu", weights_only=True)
    return state["model"]
