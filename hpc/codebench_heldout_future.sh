#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Build a fresh held-out set (test3) from GitHub Advisory Database advisories published AFTER a cutoff, the way test2
# was built, so rules tuned on everything up to the cutoff can be judged once on advisories that did not exist yet.
# Stages (run in this order; the evaluation itself is a separate, deliberate step and is only printed here):
#   bash hpc/codebench_heldout_future.sh clone    # on the transfer node: fresh advisory-database checkout
#   bash hpc/codebench_heldout_future.sh select   # login node: submits the offline selection job
#   bash hpc/codebench_heldout_future.sh fetch    # on the transfer node: the fix commits (partial clones)
#   bash hpc/codebench_heldout_future.sh build    # login node: submits the offline build job
#   bash hpc/codebench_heldout_future.sh eval     # prints the one-time evaluation command (does not run it)
# Environment: CUTOFF (default 2026-10-22; advisories must be published after it), KESTRIX_CODE (default
# ~/kestrix-codebench), ROOT3 (default /scratch/$USER/kestrix/codebench3). Run `select` only when advisories newer than
# the cutoff exist (its report says how many). The builder names every such set "test2" in its manifest and report
# (`split` field); the evaluation name (test3-v1) tells them apart. `ssh explorer-xfer` for clone and fetch, `ssh explorer` for the rest.
set -euo pipefail
STAGE="${1:?usage: bash hpc/codebench_heldout_future.sh clone|select|fetch|build|eval}"
CUTOFF="${CUTOFF:-2026-10-22}"
CODE="${KESTRIX_CODE:-$HOME/kestrix-codebench}"
ROOT3="${ROOT3:-/scratch/$USER/kestrix/codebench3}"
OLD="/scratch/$USER/kestrix/codebench"
umask 077
mkdir -p "$ROOT3/logs" "$ROOT3/raw"
case "$STAGE" in
  clone)
    module load git/2.19.0 2>/dev/null || true
    rm -rf "$ROOT3/raw/ghsa"
    git clone --depth=1 --filter=blob:none https://github.com/github/advisory-database "$ROOT3/raw/ghsa"
    git -C "$ROOT3/raw/ghsa" rev-parse HEAD | tee "$ROOT3/raw/ghsa.HEAD"
    ;;
  select)
    sbatch --export=ALL,STAGE=select,KESTRIX_CODE="$CODE",KESTRIX_CODEBENCH="$ROOT3" \
      --output="$ROOT3/logs/%x-%j.out" "$CODE/hpc/codebench2_prep.sbatch" --published-after "$CUTOFF" --allow-known-repos --allow-morefixes
    ;;
  fetch)
    KESTRIX_CODE="$CODE" KESTRIX_CODEBENCH="$ROOT3" nohup bash -l "$CODE/hpc/codebench2_fetch.sh" > "$ROOT3/logs/fetch.log" 2>&1 &
    echo "fetching in the background; log $ROOT3/logs/fetch.log"
    ;;
  build)
    sbatch --export=ALL,STAGE=build,KESTRIX_CODE="$CODE",KESTRIX_CODEBENCH="$ROOT3" \
      --output="$ROOT3/logs/%x-%j.out" "$CODE/hpc/codebench2_prep.sbatch"
    ;;
  eval)
    echo "One-time evaluation (claims $ROOT3/reports/LOCKED_EVAL_TEST2.json; a second run is refused). Freeze the code first:"
    echo "KESTRIX_CODE=$CODE KESTRIX_CODEBENCH=$ROOT3 sbatch --export=ALL --output=$ROOT3/logs/%x-%j.out $CODE/hpc/codebench2_locked.sbatch --name test3-v1 --kestrix-tree base=PATH_TO_BASELINE_TREE"
    ;;
  *) echo "unknown stage $STAGE" >&2; exit 2 ;;
esac
