#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure a code tree on the Phase 5 benchmark's dev split (C, C++, Rust, Swift): the kestrix scan array, then the dev
# metrics (with the flawfinder and opengrep-sys runs named in FLAWFINDER_RUN and OPENGREP_RUN, when set), the per-rule
# rates and (when BASE_RUN is set) the paired change against that run. Everything runs under Slurm; this only submits.
#   KESTRIX_CODE=/scratch/$USER/kestrix-sys/code bash research/hpc/codebench/codebench_p5_round.sh LABEL [BASE_RUN]
# TOOL=flawfinder (or opengrep-sys) scans with that tool instead and writes no metrics.
set -euo pipefail
LABEL="${1:?usage: bash research/hpc/codebench/codebench_p5_round.sh LABEL [BASE_RUN]}"
BASE_RUN="${2:-}"
: "${KESTRIX_CODE:?set KESTRIX_CODE}"
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix-sys/codebench-p5}"
LOGS="$KESTRIX_CODEBENCH/logs"
mkdir -p "$LOGS"
common=(--account=aai6610.202610 --partition=short --export=ALL)
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
TOOL="${TOOL:-kestrix}"
scan=$(sb --parsable "${common[@]}" --job-name="kx-p5-$TOOL" --output="$LOGS/%x-%A_%a.out" --export=ALL,TOOL="$TOOL",RUN="$LABEL",SPLIT=dev "$KESTRIX_CODE/research/hpc/codebench/codebench_scan.sbatch")
if [ "$TOOL" != kestrix ]; then echo "$LABEL $TOOL scan $scan" | tee -a "$LOGS/rounds.ids"; exit 0; fi
run="source $KESTRIX_CODE/research/hpc/codebench/codebench_env.sh; "
tools=kestrix
runs="--tool-run kestrix=$LABEL"
if [ -n "${FLAWFINDER_RUN:-}" ]; then tools="$tools,flawfinder"; runs="$runs --tool-run flawfinder=$FLAWFINDER_RUN"; fi
if [ -n "${OPENGREP_RUN:-}" ]; then tools="$tools,opengrep-sys"; runs="$runs --tool-run opengrep-sys=$OPENGREP_RUN"; fi
dev=$(sb --parsable "${common[@]}" --mem=32G --time=02:00:00 --job-name=kx-p5-dev --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb dev-metrics dev-metrics --root \$CB --label p5-$LABEL --tools $tools $runs")
rates=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name=kx-p5-rates --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
  --wrap="$run cb rule-rates rule-rates --root \$CB --run $LABEL --split dev --label p5-$LABEL")
ids="$LABEL scan $scan dev-metrics $dev rates $rates"
if [ -n "$BASE_RUN" ]; then
  cmp=$(sb --parsable "${common[@]}" --mem=32G --time=02:00:00 --job-name=kx-p5-cmp --output="$LOGS/%x-%j.out" --dependency=afterok:"$scan" \
    --wrap="$run cb compare compare --root \$CB --base-run $BASE_RUN --run $LABEL --label p5-$LABEL --split dev")
  ids="$ids compare $cmp"
fi
echo "$ids" | tee -a "$LOGS/rounds.ids"
