#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-natural
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Mines SigmaHQ history for natural maintenance faults (reports/natural-mining.json) and verifies
# every pair against the global pool of verified positives (reports/natural-verified.json, ids only).
# Run before hpc/review_split.sbatch so verified rules join the split; hpc/variants.sbatch then
# writes the natural cases.
set -euo pipefail
source "$HOME/kestrix/hpc/engine.sh"
uv run --no-sync python -m kestrixbench natural-mine --root "$DATA"
uv run --no-sync python -m kestrixbench natural-verify --root "$DATA" --es-url "$ES_URL"
