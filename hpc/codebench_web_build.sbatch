#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbweb-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-web/logs/%x-%j.out
# Web-file benchmark (.vue .svelte .html .htm .css .scss pairs of CVE fix commits) in its own root, so the ids and the
# split of the Python/JavaScript/TypeScript benchmark stay as they were: the same filters and sources, `--only-language
# web`. The round-1 test of that benchmark is spent (LOCKED_EVAL.json), and every web pair is tuning data, so the claim
# file is copied for `--split tuning`.
#   sbatch --export=ALL,KESTRIX_CODE=$HOME/cbweb/final hpc/codebench_web_build.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-web}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/reports"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/hpc/codebench_env.sh"
cb build build --root "$CB" --cvefixes-db "$VUL/work/cvefixes.sqlite" --vul-root "$VUL" --only-language web "$@"
cp "/scratch/$USER/kestrix/codebench/reports/LOCKED_EVAL.json" "$CB/reports/LOCKED_EVAL.json"
