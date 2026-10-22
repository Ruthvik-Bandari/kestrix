#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Submit one rule-round measurement from the code tree in $KESTRIX_CODE (default ~/kestrix) on the login node:
#   bash hpc/mail_round.sh NAME    dev features (array) -> dev metrics, under /scratch/$USER/kestrix/mailbench-rules/NAME
# Reads the benchmark's private work/ (symlinked) and writes only to the round root. Never touches the locked test.
set -euo pipefail
umask 077
NAME="${1:?usage: bash hpc/mail_round.sh NAME}"
BASE="/scratch/$USER/kestrix/mailbench"
ROOT="/scratch/$USER/kestrix/mailbench-rules/$NAME"
mkdir -p "$ROOT/reports" "$ROOT/features" "$BASE/logs"
ln -sfn "$BASE/work" "$ROOT/work"
cp "$BASE/reports/split-manifest.json" "$ROOT/reports/split-manifest.json"
export KESTRIX_MAILBENCH="$ROOT"
cd "$(dirname "$0")/.."
feats=$(sbatch --parsable hpc/mail_round_features.sbatch)
dev=$(sbatch --parsable --dependency=afterok:"$feats" hpc/mail_dev_metrics.sbatch)
echo "$NAME features $feats dev-metrics $dev" | tee -a "$BASE/logs/rules.ids"
