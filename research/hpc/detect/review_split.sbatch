#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-review-split
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# After research/hpc/detect/replay.sbatch: writes the private OTRF review sheet (never overwrites labels.csv),
# reports review progress (counts only) and writes the split preview. Freezing is a separate,
# deliberate step: `python -m kestrixbench split --freeze --root ...`.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
DATA="${KESTRIX_DATA:-/scratch/$USER/kestrix/data}"  # override for a separate run, e.g. the sensitivity check
uv run --no-sync python -m kestrixbench review-sheet --root "$DATA"
uv run --no-sync python -m kestrixbench review-status --root "$DATA" || true  # unreviewed rows are expected at first
uv run --no-sync python -m kestrixbench split --root "$DATA"
