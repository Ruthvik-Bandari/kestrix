#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-features
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --array=0-15
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%A_%a.out
# One array task per corpus shard: kestrix.mail.analyze over every message (offline), writing features/ only
# (verdict, score, finding ids and severities, counts; no text). Run after hpc/mail_build.sbatch.
set -euo pipefail
source "$HOME/kestrix/hpc/mail_env.sh"
mb "features shard $SLURM_ARRAY_TASK_ID" features --root "$MB" --shard "$SLURM_ARRAY_TASK_ID"
