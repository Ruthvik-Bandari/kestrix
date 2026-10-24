#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-round-features
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --array=0-15
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%A_%a.out
# Rule rounds: one array task per shard, dev messages only (the locked test is never analyzed). Needs
# KESTRIX_MAILBENCH (the round root, made by research/hpc/mail/mail_round.sh) and optionally KESTRIX_CODE.
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix}/research/hpc/mail/mail_env.sh"
mb "round features shard $SLURM_ARRAY_TASK_ID" features --root "$MB" --shard "$SLURM_ARRAY_TASK_ID" --splits dev
