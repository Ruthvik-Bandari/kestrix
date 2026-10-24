#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbweb-corpus
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-web/logs/%x-%j.out
# Alerts per KLOC of the web rules on web files nothing in the CVE data touched: third-party packages already on the
# cluster (Python site-packages, node_modules). LABEL names the report (reports/codebench-webcorpus-LABEL.json).
#   sbatch --export=ALL,KESTRIX_CODE=$HOME/cbweb/final,LABEL=final research/hpc/codebench/codebench_web_corpus.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-web}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/reports"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: "${LABEL:?set LABEL}"
dirs=()
for d in "$HOME/kestrix/.venv/lib" "/scratch/$USER/kestrix/venv-gpu/lib" "/scratch/$USER/kestrix/codebench/tools"; do
  if [ -d "$d" ]; then dirs+=(--corpus-dir "$d"); fi
done
cb "web-corpus $LABEL" web-corpus --root "$CB" --label "$LABEL" "${dirs[@]}"
