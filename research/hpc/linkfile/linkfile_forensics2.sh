#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Measure the forensics-gaps round on the login node: the shipped rules (code $CODE_ROOT/base, forensics from main)
# beside the new rules (code $CODE_ROOT/final), each in its own root under /scratch/$USER/kestrix/linkfilebench-rules/:
#   bash research/hpc/linkfile/linkfile_forensics2.sh file      build the file work (the synthetic families changed), dev features, dev metrics
#   bash research/hpc/linkfile/linkfile_forensics2.sh link      dev features and dev metrics of the link benchmark (work reused, never rebuilt)
#   bash research/hpc/linkfile/linkfile_forensics2.sh realurl   build the Common Crawl URL sample and split it, dev features and dev metrics
# DEV_ARGS="--bootstrap 100" shortens the dev metrics of candidates (the link ones take over an hour at 1000 resamples).
# BUILD_DEP=JOBID makes SKIP_BUILD runs wait for a build already submitted.
# VARIANTS="final" (or a candidate name such as m1, whose code tree $CODE_ROOT/m1 you made)  reruns only the new rules; SKIP_BUILD=1 reuses the built work (a rule change that leaves the data alone).
# Only the dev split is analyzed here; the test split of realurl is read only by research/hpc/linkfile/linkfile_locked.sh --kinds realurl.
set -euo pipefail
# Code trees live on /scratch (the home quota was full): $CODE_ROOT/final, base (shipped rules) and one per candidate.
CODE_ROOT="${CODE_ROOT:-/scratch/$USER/kestrix/forensics2-code}"
umask 077
KIND="${1:?usage: bash research/hpc/linkfile/linkfile_forensics2.sh file|link|realurl}"
BASE="/scratch/$USER/kestrix/linkfilebench"
RULES="/scratch/$USER/kestrix/linkfilebench-rules"
FINAL="$RULES/forensics2-final"
OLD="$RULES/forensics2-base"
mkdir -p "$FINAL/$KIND/reports" "$FINAL/$KIND/features" "$OLD/$KIND/reports" "$OLD/$KIND/features" "$BASE/logs"
for root in "$FINAL" "$OLD"; do ln -sfn "$BASE/raw" "$root/raw"; done
case "$KIND" in link) last=15 ;; file) last=19 ;; realurl) last=3 ;; *) echo "bad kind" >&2; exit 2 ;; esac
CODE_FINAL="$CODE_ROOT/final"
CODE_OLD="$CODE_ROOT/base"
cd "$CODE_FINAL"
run() { # root code then the sbatch arguments
  local root="$1" code="$2"; shift 2
  KESTRIX_LINKFILEBENCH="$root" KESTRIX_CODE="$code" sbatch --parsable "$@"
}
dep=()
if [ -n "${SKIP_BUILD:-}" ]; then
  [ -n "${BUILD_DEP:-}" ] && dep=(--dependency=afterok:"$BUILD_DEP")  # a build submitted earlier
elif [ "$KIND" = link ]; then
  for root in "$FINAL" "$OLD"; do
    ln -sfn "$BASE/link/work" "$root/link/work"
    cp "$BASE/link/reports/split-manifest.json" "$root/link/reports/split-manifest.json"
  done
else
  build=$(run "$FINAL" "$CODE_FINAL" "$CODE_FINAL/research/hpc/linkfile/linkfile_build.sbatch" "$KIND")
  ln -sfn "$FINAL/$KIND/work" "$OLD/$KIND/work"
  dep=(--dependency=afterok:"$build")
  echo "build $build" | tee -a "$BASE/logs/forensics2.ids"
fi
for variant in ${VARIANTS:-final old}; do
  case "$variant" in
    final) root="$FINAL"; code="$CODE_FINAL" ;;
    old) root="$OLD"; code="$CODE_OLD" ;;
    *) # a candidate: its own code tree $CODE_ROOT/NAME and root forensics2-NAME beside the others
       root="$RULES/forensics2-$variant"; code="$CODE_ROOT/$variant"
       mkdir -p "$root/$KIND/reports" "$root/$KIND/features"; ln -sfn "$BASE/raw" "$root/raw"
       ln -sfn "$FINAL/$KIND/work" "$root/$KIND/work"
       cp -n "$FINAL/$KIND/reports/split-manifest.json" "$root/$KIND/reports/" 2>/dev/null || true ;;
  esac
  feats=$(run "$root" "$code" "${dep[@]}" --array=0-$last --job-name="kestrix-lf2-feat-$variant" "$code/research/hpc/linkfile/linkfile_features.sbatch" "$KIND" dev)
  devm=$(run "$root" "$code" --dependency=afterok:"$feats" --job-name="kestrix-lf2-dev-$variant" "$code/research/hpc/linkfile/linkfile_dev_metrics.sbatch" "$KIND" ${DEV_ARGS:-})
  echo "$KIND $variant features $feats dev-metrics $devm" | tee -a "$BASE/logs/forensics2.ids"
done
