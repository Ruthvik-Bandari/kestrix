#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-variants
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --array=0-15
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%A_%a.out
# Proposed rule changes, applied by monkeypatch in the bench (src/kestrix/mail untouched), over dev only.
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/hpc/modern_env.sh"
mm "variants $SLURM_ARRAY_TASK_ID" variants --shard "$SLURM_ARRAY_TASK_ID"
