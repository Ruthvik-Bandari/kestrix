#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# THE REAL-URL LOCKED TEST. Run once, on the login node, after the dev measurement settled the rules:
#   bash research/hpc/linkfile/linkfile_realurl_locked.sh --name realurl-v1 [--dry-run]
# Test features of the final rules (root linkfilebench-rules/forensics2-final, code $CODE_ROOT/final) and of the
# shipped rules (root forensics2-base, code $CODE_ROOT/base), then the evaluation (afterok both), which claims
# <root>/realurl/reports/LOCKED_EVAL.json with an exclusive create and refuses a second run. It also refuses when a
# root's dev and test features come from different code versions. --dry-run only prints the submissions.
set -euo pipefail
# Code trees live on /scratch (the home quota was full): $CODE_ROOT/final, base (shipped rules) and one per candidate.
CODE_ROOT="${CODE_ROOT:-/scratch/$USER/kestrix/forensics2-code}"
umask 077
NAME="realurl-v1"; DRY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --dry-run) DRY=echo; shift ;;
    *) echo "usage: bash research/hpc/linkfile/linkfile_realurl_locked.sh --name NAME [--dry-run]" >&2; exit 2 ;;
  esac
done
BASE="/scratch/$USER/kestrix/linkfilebench"
RULES="/scratch/$USER/kestrix/linkfilebench-rules"
FINAL="$RULES/forensics2-final"; OLD="$RULES/forensics2-base"
FINAL_CODE="$CODE_ROOT/final"; OLD_CODE="$CODE_ROOT/base"
for d in "$FINAL_CODE" "$OLD_CODE" "$FINAL/realurl/reports/realurl-dev-metrics.json" "$OLD/realurl/reports/realurl-dev-metrics.json"; do
  [ -e "$d" ] || { echo "missing $d: run research/hpc/linkfile/linkfile_forensics2.sh realurl first" >&2; exit 2; }
done
cp -n "$FINAL/realurl/reports/split-manifest.json" "$OLD/realurl/reports/split-manifest.json"  # must be byte-identical
cd "$FINAL_CODE"
deps=""
for variant in final baseline; do
  if [ "$variant" = final ]; then root="$FINAL"; code="$FINAL_CODE"; else root="$OLD"; code="$OLD_CODE"; fi
  id=$(KESTRIX_LINKFILEBENCH="$root" KESTRIX_CODE="$code" $DRY sbatch --parsable --array=0-3 \
       --job-name="kestrix-lf-test-feat-$variant" "$FINAL_CODE/research/hpc/linkfile/linkfile_features.sbatch" realurl test)
  deps="$deps:$id"
done
id=$(KESTRIX_LINKFILEBENCH="$FINAL" KESTRIX_CODE="$FINAL_CODE" $DRY sbatch --parsable --dependency=afterok$deps \
     "$FINAL_CODE/research/hpc/linkfile/linkfile_locked.sbatch" realurl --name "$NAME" --baseline-root "$OLD")
echo "realurl: test features$deps, locked evaluation $id" | tee -a "$BASE/logs/locked.ids"
