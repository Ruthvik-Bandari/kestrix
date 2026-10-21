#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-student
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:a100:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=48G
#SBATCH --time=03:00:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# C6 student: UniXcoder-base distilled from the teacher run(s), permissive-license pool only (src/kestrixvul/train.py).
#   sbatch hpc/vul_train_student.sbatch --teacher-run teacher-seed1-<job> [--teacher-run ...]
# Several teacher runs are averaged (mean logit). Needs hpc/fetch_vul_student_model.sh (transfer node).
# Writes $VUL/runs/student-seed<S>-<job>/ (run.json, log.jsonl, student_fp32.pt, student_int8.pt).
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
/usr/bin/time -f "train student: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul.train student \
  --root "$VUL" "$@"
