#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp5-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=64G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix-sys/codebench-p5/logs/%x-%j.out
# Phase 5 benchmark (C, C++, Rust and Swift pairs of CVEfixes fix commits) in its own root: the same filters and the
# project-disjoint seeded split as the other benchmarks, `--only-language p5`, from the working database that
# codebench_p5_dump.sbatch wrote. The test split is written but not read until `locked-test`.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix-sys/code research/hpc/codebench/codebench_p5_build.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix-sys/codebench-p5}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/reports"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
cb build build --root "$CB" --cvefixes-db "$CB/work/cvefixes_p5.sqlite" --vul-root "$CB/vul" --only-language p5 "$@"
