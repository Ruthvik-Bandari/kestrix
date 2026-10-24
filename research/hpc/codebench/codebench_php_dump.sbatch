#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbphp-dump
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-php/logs/%x-%j.out
# Stream the pinned CVEfixes archive once more and keep only the PHP file changes (kestrixvul's working database keeps
# Python, JavaScript and TypeScript). Writes $CB/work/cvefixes_php.sqlite (private) and an empty advisory root, because
# the advisory miner fetches no PHP.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/php/code research/hpc/codebench/codebench_php_dump.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-php}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/work" "$KESTRIX_CODEBENCH/vul/work" "$KESTRIX_CODEBENCH/vul/mine"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: > "$CB/vul/work/ghsa.jsonl"
: > "$CB/vul/work/mine_targets.jsonl"
cb php-dump php-dump --cvefixes-zip "$VUL/raw/cvefixes/CVEfixes_v1.0.8.zip" --out "$CB/work/cvefixes_php.sqlite"
