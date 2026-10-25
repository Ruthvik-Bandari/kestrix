#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp5-dump
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix-sys/codebench-p5/logs/%x-%j.out
# Phase 5: stream the pinned CVEfixes archive once more and keep the C, C++, Rust and Swift file changes (and any file
# ending in .rs or .swift). Writes $CB/work/cvefixes_p5.sqlite (private) and an empty advisory root, because the advisory
# miner fetches none of these languages.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix-sys/code research/hpc/codebench/codebench_p5_dump.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix-sys/codebench-p5}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/work" "$KESTRIX_CODEBENCH/vul/work" "$KESTRIX_CODEBENCH/vul/mine"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: > "$CB/vul/work/ghsa.jsonl"
: > "$CB/vul/work/mine_targets.jsonl"
cb p5-dump php-dump --label-set p5 --cvefixes-zip "$VUL/raw/cvefixes/CVEfixes_v1.0.8.zip" --out "$CB/work/cvefixes_p5.sqlite"
