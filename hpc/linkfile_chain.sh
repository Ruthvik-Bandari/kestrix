#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Submit the link and file benchmark chains from ~/kestrix-linkfile on the login node:
#   bash hpc/linkfile_chain.sh smoke   a small build per kind (a few hundred items), then stop
#   bash hpc/linkfile_chain.sh full    build -> dev features (array) -> dev metrics, per kind, each afterok the last
# Job ids are printed and appended to $LB/logs/chain.ids. Only dev features are made here: the locked test is
# never analyzed, and hpc/linkfile_locked.sh is the only script that touches it.
set -euo pipefail
umask 077
LB="${KESTRIX_LINKFILEBENCH:-/scratch/$USER/kestrix/linkfilebench}"
mkdir -p "$LB/logs"   # Slurm drops output silently when the log directory is missing
case "${1:-}" in
  smoke)
    id=$(sbatch --parsable hpc/linkfile_smoke.sbatch)
    echo "smoke $id" | tee -a "$LB/logs/chain.ids" ;;
  full)
    for kind in link file; do
      [ "$kind" = link ] && last=15 || last=19
      build=$(sbatch --parsable hpc/linkfile_build.sbatch "$kind")
      feats=$(sbatch --parsable --dependency=afterok:"$build" --array=0-$last hpc/linkfile_features.sbatch "$kind" dev)
      dev=$(sbatch --parsable --dependency=afterok:"$feats" hpc/linkfile_dev_metrics.sbatch "$kind")
      echo "$kind build $build features $feats dev-metrics $dev" | tee -a "$LB/logs/chain.ids"
    done ;;
  *) echo "usage: bash hpc/linkfile_chain.sh smoke|full" >&2; exit 2 ;;
esac
