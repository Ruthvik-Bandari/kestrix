#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-teacher
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=06:00:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# C6 teacher: LoRA on Qwen2.5-Coder-7B-Instruct (bf16, gradient checkpointing, up to 4096 tokens) on one H200
# (src/kestrixvul/train.py). One seed per job; three seeds as an array (seed = array index):
#   sbatch --array=1-3 hpc/vul_train_teacher.sbatch
# Extra arguments go to `python -m kestrixvul.train teacher` (e.g. --view filtered, --lora-r 32).
# Writes $VUL/runs/teacher-seed<S>-<job>/ (run.json, log.jsonl, best/, last/, soft_labels.jsonl).
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
SEED="${SLURM_ARRAY_TASK_ID:-1}"
/usr/bin/time -f "train teacher: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul.train teacher \
  --root "$VUL" --seed "$SEED" --run-id "teacher-seed$SEED-${SLURM_ARRAY_JOB_ID:-$SLURM_JOB_ID}" "$@"
