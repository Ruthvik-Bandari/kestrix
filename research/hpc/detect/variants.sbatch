#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-variants
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Generates and verifies the impairment cases for every root in the split (benchmark/cases/, private)
# and writes reports/variants.json, then writes natural cases when research/hpc/detect/natural.sbatch has run. Uses the frozen split when it exists, else pass a manifest:
#   sbatch research/hpc/detect/variants.sbatch reports/split-preview.json
set -euo pipefail
source "$HOME/kestrix/research/hpc/detect/engine.sh"
ARGS=()
[ $# -ge 1 ] && ARGS=(--manifest "$DATA/$1")
uv run --no-sync python -m kestrixbench variants --root "$DATA" --es-url "$ES_URL" "${ARGS[@]}"
if [ -f "$DATA/reports/natural-verified.json" ]; then
  uv run --no-sync python -m kestrixbench natural-build --root "$DATA" "${ARGS[@]}"
fi
