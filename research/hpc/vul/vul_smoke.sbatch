#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-smoke
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=00:20:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# C6 smoke, end to end in under 20 minutes: teacher (20 steps on 200 train examples), the student (20 steps)
# when its snapshot is present, then the dev evaluation on 100 examples with every system.
#   sbatch [--dependency=afterok:<split job>] research/hpc/vul/vul_smoke.sbatch
set -euo pipefail
source "$HOME/kestrix/research/hpc/common/gpu_env.sh"
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export PYTHONPATH="$HOME/kestrix/src:$HOME/kestrix/packages/kestrix-scan/src"
if [ -f "$HOME/kestrix/GIT_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$HOME/kestrix/GIT_SHA")"; fi
umask 077
cd "$HOME/kestrix"
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
mkdir -p "$VUL/logs" "$VUL/runs"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
RUN="smoke-$SLURM_JOB_ID"
uv run --no-sync python -m kestrixvul.train teacher --root "$VUL" --run-id "$RUN" --epochs 1 --max-steps 20 \
  --limit 200 --dev-limit 100 --dev-neg-ratio 3 --micro-batch 2 --grad-accumulation 2 --eval-every 10 --log-every 5
EVAL=(--teacher-run "$RUN")
if [ -f "/scratch/$USER/kestrix/models/unixcoder-base@5604afdc964f6c53782a6813140ade5216b99006/MANIFEST.sha256" ]; then
  uv run --no-sync python -m kestrixvul.train student --root "$VUL" --teacher-run "$RUN" --run-id "$RUN-student" \
    --epochs 1 --max-steps 20 --dev-limit 100 --batch 8 --log-every 5
  EVAL+=(--student-run "$RUN-student" --latency-n 20)
else
  echo "student snapshot not present yet: skipping the student smoke"
fi
uv run --no-sync python -m kestrixvul.evaluate --root "$VUL" --name "$RUN" --zero-shot "${EVAL[@]}" \
  --limit 100 --dev-neg-ratio 3 --bootstrap 50
echo "smoke done: $VUL/runs/$RUN $VUL/reports/vul-eval-$RUN.json"
