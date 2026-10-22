#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Submit one rule-round measurement on the login node, from the code tree in ~/kestrix-linkfile-rounds/NAME:
#   bash hpc/linkfile_round.sh NAME link|file    dev features (array) -> dev metrics, under
#                                                /scratch/$USER/kestrix/linkfilebench-rules/NAME
# The round root reads the benchmark's private work/ and raw/ (symlinked) and its split manifest (copied) and writes
# only to itself. Only the dev split is analyzed: the locked test is never touched.
set -euo pipefail
umask 077
NAME="${1:?usage: bash hpc/linkfile_round.sh NAME link|file}"
KIND="${2:?usage: bash hpc/linkfile_round.sh NAME link|file}"
BASE="/scratch/$USER/kestrix/linkfilebench"
ROOT="/scratch/$USER/kestrix/linkfilebench-rules/$NAME"
CODE_DIR="$HOME/kestrix-linkfile-rounds/$NAME"
[ -d "$CODE_DIR" ] || { echo "no code tree $CODE_DIR" >&2; exit 2; }
mkdir -p "$ROOT/$KIND/reports" "$ROOT/$KIND/features" "$BASE/logs"
ln -sfn "$BASE/raw" "$ROOT/raw"
ln -sfn "$BASE/$KIND/work" "$ROOT/$KIND/work"
cp "$BASE/$KIND/reports/split-manifest.json" "$ROOT/$KIND/reports/split-manifest.json"
export KESTRIX_LINKFILEBENCH="$ROOT" KESTRIX_CODE="$CODE_DIR"
cd "$CODE_DIR"
[ "$KIND" = link ] && last=15 || last=19
feats=$(sbatch --parsable --array=0-$last hpc/linkfile_features.sbatch "$KIND" dev)
dev=$(sbatch --parsable --dependency=afterok:"$feats" hpc/linkfile_dev_metrics.sbatch "$KIND")
echo "$NAME $KIND features $feats dev-metrics $dev" | tee -a "$BASE/logs/rules.ids"
