#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure a code tree on the Phase 4 benchmark's dev split (Go, Java, Kotlin, C#, Ruby, ERB): the kestrix scan array, then
# the dev metrics (with the gosec and opengrep runs named in GOSEC_RUN and OPENGREP_RUN, when set), the per-rule rates and
# (when BASE_RUN is set) the paired change against that run. Everything runs under Slurm; this only submits.
#   KESTRIX_CODE=/scratch/$USER/kestrix/p4/code bash research/hpc/codebench/codebench_p4_round.sh LABEL [BASE_RUN]
set -euo pipefail
LABEL="${1:?usage: bash research/hpc/codebench/codebench_p4_round.sh LABEL [BASE_RUN]}"
BASE_RUN="${2:-}"
: "${KESTRIX_CODE:?set KESTRIX_CODE}"
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-p4}"
LOGS="$KESTRIX_CODEBENCH/logs"
mkdir -p "$LOGS"
common=(--account=aai6610.202610 --partition=short --export=ALL)
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
scan=$(sb --parsable "${common[@]}" --output="$LOGS/%x-%A_%a.out" --export=ALL,TOOL=kestrix,RUN="$LABEL",SPLIT=dev "$KESTRIX_CODE/research/hpc/codebench/codebench_scan.sbatch")
run="source $KESTRIX_CODE/research/hpc/codebench/codebench_env.sh; "
tools=kestrix
runs="--tool-run kestrix=$LABEL"
if [ -n "${GOSEC_RUN:-}" ]; then tools="$tools,gosec"; runs="$runs --tool-run gosec=$GOSEC_RUN"; fi
if [ -n "${OPENGREP_RUN:-}" ]; then tools="$tools,opengrep"; runs="$runs --tool-run opengrep=$OPENGREP_RUN"; fi
dev=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name=kx-p4-dev --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb dev-metrics dev-metrics --root \$CB --label p4-$LABEL --tools $tools $runs")
rates=$(sb --parsable "${common[@]}" --mem=8G --time=01:00:00 --job-name=kx-p4-rates --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb rule-rates rule-rates --root \$CB --run $LABEL --split dev --label p4-$LABEL")
ids="$LABEL scan $scan dev-metrics $dev rates $rates"
if [ -n "$BASE_RUN" ]; then
  cmp=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name=kx-p4-cmp --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
    --wrap="$run cb compare compare --root \$CB --base-run $BASE_RUN --run $LABEL --label p4-$LABEL --split dev")
  ids="$ids compare $cmp"
fi
echo "$ids" | tee -a "$LOGS/rounds.ids"
