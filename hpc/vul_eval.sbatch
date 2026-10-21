#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-eval
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# C6 evaluation (src/kestrixvul/evaluate.py): dev by default, every baseline, plus the given runs:
#   sbatch hpc/vul_eval.sbatch --zero-shot --teacher-run <id> [--teacher-run <id> ...] --student-run <id>
# The one-time held-out test (claims $VUL/reports/LOCKED_EVAL.json and refuses a second time):
#   sbatch hpc/vul_eval.sbatch --split test --locked --teacher-run <id> --student-run <id>
# Writes $VUL/reports/vul-eval-<name>.json and the scores under $VUL/eval/<name>/ (0600).
set -euo pipefail
source "$HOME/kestrix/hpc/gpu_env.sh"
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export PYTHONPATH="$HOME/kestrix/src:$HOME/kestrix/packages/kestrix-scan/src"
if [ -f "$HOME/kestrix/GIT_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$HOME/kestrix/GIT_SHA")"; fi
umask 077
cd "$HOME/kestrix"
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
mkdir -p "$VUL/logs" "$VUL/runs"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
/usr/bin/time -f "evaluate: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul.evaluate --root "$VUL" "$@"
