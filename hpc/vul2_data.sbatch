#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul2-data
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/vul2/logs/%x-%j.out
# Round 2 data, offline (src/kestrixvul/round2.py), code in /scratch/$USER/kestrix/vul2-code (never ~/kestrix):
#   build-test2  extract the codebench2 fix commits, dedup against the C6 pool, project-disjoint tiers, freeze test-v2
#   split        round-2 train / validation split (refuses before test-v2 is frozen)
#   sbatch hpc/vul2_data.sbatch build-test2|split
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
export UV_CACHE_DIR="/scratch/$USER/kestrix/uv-cache" UV_PROJECT_ENVIRONMENT="/scratch/$USER/kestrix/venv-gpu"
CODE="${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}"
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src"
if [ -f "$CODE/GIT_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$CODE/GIT_SHA")"; fi
umask 077
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
VUL2="${KESTRIX_VUL2:-/scratch/$USER/kestrix/vul2}"
CB2="${KESTRIX_CB2:-/scratch/$USER/kestrix/codebench2}"
mkdir -p "$VUL2/logs" "$VUL2/runs" "$VUL2/reports" "$VUL2/work"
cd "$CODE"
case "${1:-}" in
  build-test2) /usr/bin/time -f "build-test2: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul.round2 build-test2 --root "$VUL2" --vul-root "$VUL" --codebench-root "$CB2" "${@:2}" ;;
  split)
    [ -e "$VUL2/licenses" ] || ln -s "$VUL/licenses" "$VUL2/licenses"
    /usr/bin/time -f "split: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul.round2 split --root "$VUL2" --vul-root "$VUL" ;;
  *) echo "usage: sbatch hpc/vul2_data.sbatch build-test2|split" >&2; exit 2 ;;
esac
ls -l "$VUL2/work" "$VUL2/reports"
