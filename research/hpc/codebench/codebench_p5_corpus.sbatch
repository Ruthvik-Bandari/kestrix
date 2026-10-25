#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp5-corpus
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix-sys/codebench-p5/logs/%x-%j.out
# Findings per KLOC of the Phase 5 rules on C, C++, Rust, Swift and property-list files no CVE fix touched: shallow
# clones of popular projects under $CORPUS (one report per project directory). LABEL prefixes the reports.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix-sys/code,LABEL=final research/hpc/codebench/codebench_p5_corpus.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix-sys/codebench-p5}"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: "${LABEL:?set LABEL}"
CORPUS="${CORPUS:-/scratch/$USER/kestrix-sys/corpus}"
for project in "$CORPUS"/*/; do
  name="$(basename "$project")"
  cb "p5-corpus $name" p5-corpus --root "$CB" --label "$LABEL-$name" --corpus-dir "$project"
done
