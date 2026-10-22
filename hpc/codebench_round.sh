#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure the synced code tree on dev: kestrix scan array, then dev metrics against the baselines' "base" run and the
# paired change against the kestrix run named by BASE_RUN (default base).
#   bash hpc/codebench_round.sh LABEL        (login node; LABEL names the run and the report)
# Baselines are scanned once with `sbatch --export=ALL,TOOL=bandit,RUN=base hpc/codebench_scan.sbatch` (and eslint).
set -euo pipefail
LABEL="${1:?usage: bash hpc/codebench_round.sh LABEL}"
cd "$(dirname "$0")/.."
scan=$(sbatch --parsable --export=ALL,TOOL=kestrix,RUN="$LABEL" hpc/codebench_scan.sbatch)
dev=$(sbatch --parsable --dependency=afterok:"$scan" hpc/codebench_dev.sbatch --label "$LABEL" \
  --tool-run kestrix="$LABEL" --tool-run bandit=base --tool-run eslint=base)
cmp=$(sbatch --parsable --dependency=afterok:"$scan" hpc/codebench_compare.sbatch --base-run "${BASE_RUN:-base}" --run "$LABEL" --label "$LABEL")
echo "$LABEL scan $scan dev-metrics $dev compare $cmp" | tee -a "/scratch/$USER/kestrix/codebench/logs/rounds.ids"
