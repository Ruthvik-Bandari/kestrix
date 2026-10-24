#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul2-smoke
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=00:25:00
#SBATCH --output=/scratch/%u/kestrix/vul2/logs/%x-%j.out
# Round-2 smoke: each new code path (pair batches, repo weights) for 20 steps, a student step, a validation eval.
set -euo pipefail
source "${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}/hpc/vul2_env.sh"
RUN="smoke-$SLURM_JOB_ID"
$PY -m kestrixvul.train teacher --root "$VUL2" --run-id "$RUN" --epochs 1 --max-steps 20 --limit 400 --dev-limit 100 \
  --micro-batch 4 --grad-accumulation 2 --eval-every 10 --log-every 5 --repo-balance 0.5 --pair-weight 1.0
$PY -m kestrixvul.train student --root "$VUL2" --teacher-run "$RUN" --run-id "$RUN-student" --epochs 1 --max-steps 10 \
  --dev-limit 100 --batch 8 --log-every 5
$PY -m kestrixvul.evaluate --root "$VUL2" --name "$RUN" --teacher-run "$RUN" --student-run "$RUN-student" \
  --limit 100 --dev-neg-ratio 3 --bootstrap 50 --latency-n 10 --ensemble 2>&1 | tail -3 || true
echo "smoke done"
