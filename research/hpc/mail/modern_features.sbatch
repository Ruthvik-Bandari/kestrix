#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-features
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --array=0-15
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%A_%a.out
# Current rules over the dev lists and the synthetic cohort (never the held-out lists).
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/research/hpc/mail/modern_env.sh"
mm "features $SLURM_ARRAY_TASK_ID" features --shard "$SLURM_ARRAY_TASK_ID" --splits dev,synthetic
