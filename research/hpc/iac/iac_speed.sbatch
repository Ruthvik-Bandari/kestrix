#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-iac-speed
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/iac/logs/%x-%j.out
# Speed with and without the Phase 3 rules on the same files, back to back on one node. OLD is the scanner source of main
# before Phase 3; NEW the Phase 3 tree.   sbatch --export=ALL,OLD=/path/old/src,NEW=/path/new/src research/hpc/iac/iac_speed.sbatch
set -euo pipefail
D=/scratch/$USER/kestrix/iac
PY=/home/bandari.ru/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu/bin/python3.12
for round in 1 2; do
  for tree in "$OLD" "$NEW"; do
    echo "$tree"; PYTHONPATH="$tree" "$PY" "$(dirname "$NEW")/../../research/hpc/iac/iac_speed.py" "$D/corpus" 6
  done
done
