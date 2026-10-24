#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul2-final
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/vul2/logs/%x-%j.out
# Round-2 final: three seeds of the recipe chosen on validation (arguments pass through), then the student
# distilled from the three-teacher ensemble.   sbatch research/hpc/vul/vul2_final.sbatch [--repo-balance 0.5] [--pair-weight 1.0]
set -euo pipefail
source "${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}/research/hpc/vul/vul2_env.sh"
J="$SLURM_JOB_ID"
for S in 1 2 3; do
  $PY -m kestrixvul.train teacher --root "$VUL2" --seed "$S" --run-id "r2-seed$S-$J" "$@" || echo "FAILED seed $S"
done
$PY -m kestrixvul.train student --root "$VUL2" --run-id "r2-student-$J" \
  --teacher-run "r2-seed1-$J" --teacher-run "r2-seed2-$J" --teacher-run "r2-seed3-$J"
