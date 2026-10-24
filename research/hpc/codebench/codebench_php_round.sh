#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure a code tree on the PHP benchmark's dev split: the kestrix scan array, then the dev metrics, the per-rule rates and
# (when BASE_RUN is set) the paired change against that run. Everything runs under Slurm; this only submits.
#   KESTRIX_CODE=/scratch/$USER/kestrix/php/code bash research/hpc/codebench/codebench_php_round.sh LABEL [BASE_RUN]
set -euo pipefail
LABEL="${1:?usage: bash research/hpc/codebench/codebench_php_round.sh LABEL [BASE_RUN]}"
BASE_RUN="${2:-}"
: "${KESTRIX_CODE:?set KESTRIX_CODE}"
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-php}"
LOGS="$KESTRIX_CODEBENCH/logs"
mkdir -p "$LOGS"
common=(--account=aai6610.202610 --partition=short --export=ALL)
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
scan=$(sb --parsable "${common[@]}" --output="$LOGS/%x-%A_%a.out" --export=ALL,TOOL=kestrix,RUN="$LABEL",SPLIT=dev "$KESTRIX_CODE/research/hpc/codebench/codebench_scan.sbatch")
run="source $KESTRIX_CODE/research/hpc/codebench/codebench_env.sh; "
# PSALM_RUN (default none): also score the Psalm scan of that run name next to kestrix
tools=kestrix
runs="--tool-run kestrix=$LABEL"
if [ -n "${PSALM_RUN:-}" ]; then tools=kestrix,psalm; runs="$runs --tool-run psalm=$PSALM_RUN"; fi
dev=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name=kx-php-dev --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb dev-metrics dev-metrics --root \$CB --label php-$LABEL --tools $tools $runs")
rates=$(sb --parsable "${common[@]}" --mem=8G --time=01:00:00 --job-name=kx-php-rates --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb rule-rates rule-rates --root \$CB --run $LABEL --split dev --label php-$LABEL")
ids="$LABEL scan $scan dev-metrics $dev rates $rates"
if [ -n "$BASE_RUN" ]; then
  cmp=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name=kx-php-cmp --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
    --wrap="$run cb compare compare --root \$CB --base-run $BASE_RUN --run $LABEL --label php-$LABEL --split dev")
  ids="$ids compare $cmp"
fi
echo "$ids" | tee -a "$LOGS/rounds.ids"
