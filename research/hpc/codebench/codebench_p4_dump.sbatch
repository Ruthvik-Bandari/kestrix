#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp4-dump
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-p4/logs/%x-%j.out
# Phase 4: stream the pinned CVEfixes archive once more and keep the Go, Java, C# and Ruby file changes (and any file
# ending in .kt, .kts or .erb, which CVEfixes does not label). Writes $CB/work/cvefixes_p4.sqlite (private) and an empty
# advisory root, because the advisory miner fetches none of these languages.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/p4/code research/hpc/codebench/codebench_p4_dump.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-p4}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/work" "$KESTRIX_CODEBENCH/vul/work" "$KESTRIX_CODEBENCH/vul/mine"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: > "$CB/vul/work/ghsa.jsonl"
: > "$CB/vul/work/mine_targets.jsonl"
cb p4-dump php-dump --label-set p4 --cvefixes-zip "$VUL/raw/cvefixes/CVEfixes_v1.0.8.zip" --out "$CB/work/cvefixes_p4.sqlite"
