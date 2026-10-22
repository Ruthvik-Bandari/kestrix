#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# THE LOCKED TEST. Run once, on the login node, only after the owner approves:
#   bash hpc/linkfile_locked.sh --name linkfile-v1 [--dry-run]
# For each kind (link, file) it submits, in order: test features of the final rules (root linkfilebench-rules/final, code
# ~/kestrix-linkfile-rounds/final) and of the baseline rules (root linkfilebench, code ~/kestrix-linkfile-base), then the locked
# evaluation (afterok both), which claims <root>/<kind>/reports/LOCKED_EVAL.json with an exclusive create and refuses
# a second run. The evaluation also refuses when a root's dev and test features come from different code versions.
# Writes linkfilebench-rules/final/<kind>/reports/<kind>-locked-<name>.json. --dry-run only prints what would be submitted.
set -euo pipefail
umask 077
NAME="linkfile-v1"; DRY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --dry-run) DRY=echo; shift ;;
    *) echo "usage: bash hpc/linkfile_locked.sh --name NAME [--dry-run]" >&2; exit 2 ;;
  esac
done
BASE="/scratch/$USER/kestrix/linkfilebench"
FINAL="/scratch/$USER/kestrix/linkfilebench-rules/final"   # the round named final: bash hpc/linkfile_round.sh final KIND
FINAL_CODE="$HOME/kestrix-linkfile-rounds/final"
BASE_CODE="$HOME/kestrix-linkfile-base"
for d in "$FINAL_CODE" "$BASE_CODE" "$FINAL/link/reports/link-dev-metrics.json" "$FINAL/file/reports/file-dev-metrics.json"; do
  [ -e "$d" ] || { echo "missing $d: run the final round (hpc/linkfile_round.sh final link|file) first" >&2; exit 2; }
done
cd "$FINAL_CODE"
for kind in link file; do
  [ "$kind" = link ] && last=15 || last=19
  deps=""
  for variant in final baseline; do
    if [ "$variant" = final ]; then root="$FINAL"; code="$FINAL_CODE"; else root="$BASE"; code="$BASE_CODE"; fi
    id=$(KESTRIX_LINKFILEBENCH="$root" KESTRIX_CODE="$code" $DRY sbatch --parsable --array=0-$last \
         --job-name="kestrix-lf-test-feat-$variant" "$FINAL_CODE/hpc/linkfile_features.sbatch" "$kind" test)
    deps="$deps:$id"
  done
  id=$(KESTRIX_LINKFILEBENCH="$FINAL" KESTRIX_CODE="$FINAL_CODE" $DRY sbatch --parsable --dependency=afterok$deps \
       "$FINAL_CODE/hpc/linkfile_locked.sbatch" "$kind" --name "$NAME" --baseline-root "$BASE")
  echo "$kind: test features$deps, locked evaluation $id" | tee -a "$BASE/logs/locked.ids"
done
