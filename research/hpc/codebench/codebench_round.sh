#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure the synced code tree on dev: kestrix scan array, then dev metrics against the baselines' "base" run and the
# paired change against the kestrix run named by BASE_RUN (default base).
#   bash research/hpc/codebench/codebench_round.sh LABEL        (login node; LABEL names the run and the report)
# Baselines are scanned once with `sbatch --export=ALL,TOOL=bandit,RUN=base research/hpc/codebench/codebench_scan.sbatch` (and eslint).
set -euo pipefail
LABEL="${1:?usage: bash research/hpc/codebench/codebench_round.sh LABEL}"
cd "$(dirname "$0")/../../.."
# the Slurm controller sometimes answers "Unexpected message received": retry a few times
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
scan=$(sb --parsable --export=ALL,TOOL=kestrix,RUN="$LABEL",SPLIT="${SPLIT:-dev}" research/hpc/codebench/codebench_scan.sbatch)
# SPLIT=tuning scores kestrix only, on round-1 dev + the spent round-1 test (the baselines were scanned on dev only)
runs=(--tool-run kestrix="$LABEL")
if [ "${SPLIT:-dev}" = dev ]; then runs+=(--tool-run bandit=base --tool-run eslint=base); fi
dev=$(sb --parsable --dependency=afterok:"$scan" research/hpc/codebench/codebench_dev.sbatch --label "$LABEL" --split "${SPLIT:-dev}" "${runs[@]}")
cmp=$(sb --parsable --dependency=afterok:"$scan" research/hpc/codebench/codebench_compare.sbatch --base-run "${BASE_RUN:-base}" --run "$LABEL" --label "$LABEL" --split "${SPLIT:-dev}")
echo "$LABEL scan $scan dev-metrics $dev compare $cmp" | tee -a "/scratch/$USER/kestrix/codebench/logs/rounds.ids"
