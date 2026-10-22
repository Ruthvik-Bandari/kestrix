#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb2-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=12:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench2/logs/%x-%j.out
# THE ONE-TIME test2 EVALUATION. Claims reports/LOCKED_EVAL_TEST2.json (exclusive create, refuses a second run), scans
# the frozen test2 set with kestrix (round-2 final: the code tree this job runs from), kestrix@r1 (the round-1 rules,
# --kestrix-tree r1=TREE), Bandit and ESLint, and writes reports/codebench-locked-NAME.json:
#   KESTRIX_CODE=$HOME/kestrix-codebench2 KESTRIX_CODEBENCH=/scratch/$USER/kestrix/codebench2 \
#     sbatch --export=ALL hpc/codebench2_locked.sbatch --name test2-v1 --kestrix-tree r1=$HOME/kestrix-codebench2-r1
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench2}/hpc/codebench_env.sh"
module load nodejs/v22.11.0
cb locked2 locked-test2 --root "$CB" "$@"
