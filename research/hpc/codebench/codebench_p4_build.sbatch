#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp4-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-p4/logs/%x-%j.out
# Phase 4 benchmark (.go .java .kt .kts .cs .rb .erb pairs of CVEfixes fix commits) in its own root: the filters and the
# project-disjoint seeded split of the other benchmarks, `--only-language p4`, from the database codebench_p4_dump.sbatch
# wrote. The test split is written but not read until `locked-test`.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/p4/code research/hpc/codebench/codebench_p4_build.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-p4}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/reports"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
cb build build --root "$CB" --cvefixes-db "$CB/work/cvefixes_p4.sqlite" --vul-root "$CB/vul" --only-language p4 "$@"
