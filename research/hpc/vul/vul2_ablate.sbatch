#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul2-ablate
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/vul2/logs/%x-%j.out
# Round-2 ablation, seed 1, selection on the project-disjoint validation split only (never test-v2):
#   v0 C6 recipe on the new split, v1 +repo balance, v2 +paired contrast, v3 both. One job, sequential.
set -euo pipefail
source "${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}/research/hpc/vul/vul2_env.sh"
J="$SLURM_JOB_ID"
run() { name="$1"; shift; $PY -m kestrixvul.train teacher --root "$VUL2" --seed 1 --run-id "abl-$name-$J" "$@" || echo "FAILED $name"; }
run v0
run v1 --repo-balance 0.5
run v2 --pair-weight 1.0
run v3 --repo-balance 0.5 --pair-weight 1.0
