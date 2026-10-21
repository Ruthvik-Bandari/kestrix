#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Submit the email benchmark chain from ~/kestrix on the login node:
#   bash hpc/mail_chain.sh smoke   one small job (a few hundred messages), then stop
#   bash hpc/mail_chain.sh full    build -> features (array) -> dev-metrics -> learn, each afterok the last
# Job ids are printed and appended to $MB/logs/chain.ids. The locked test is never submitted here.
set -euo pipefail
umask 077
MB="${KESTRIX_MAILBENCH:-/scratch/$USER/kestrix/mailbench}"
mkdir -p "$MB/logs"   # Slurm drops output silently when the log directory is missing
case "${1:-}" in
  smoke)
    id=$(sbatch --parsable hpc/mail_smoke.sbatch)
    echo "smoke $id" | tee -a "$MB/logs/chain.ids" ;;
  full)
    build=$(sbatch --parsable hpc/mail_build.sbatch)
    feats=$(sbatch --parsable --dependency=afterok:"$build" hpc/mail_features.sbatch)
    dev=$(sbatch --parsable --dependency=afterok:"$feats" hpc/mail_dev_metrics.sbatch)
    learn=$(sbatch --parsable --dependency=afterok:"$dev" hpc/mail_learn.sbatch)
    echo "build $build features $feats dev-metrics $dev learn $learn" | tee -a "$MB/logs/chain.ids" ;;
  *) echo "usage: bash hpc/mail_chain.sh smoke|full" >&2; exit 2 ;;
esac
