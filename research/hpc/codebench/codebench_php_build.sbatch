#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbphp-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-php/logs/%x-%j.out
# PHP benchmark (.php .phtml pairs of CVEfixes fix commits) in its own root: the same filters and the project-disjoint
# seeded split as the Python/JavaScript/TypeScript benchmark, `--only-language php`, from the working database that
# codebench_php_dump.sbatch wrote. The test split is written but not read until `locked-test`.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/php/code research/hpc/codebench/codebench_php_build.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-php}"
mkdir -p "$KESTRIX_CODEBENCH/logs" "$KESTRIX_CODEBENCH/reports"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
cb build build --root "$CB" --cvefixes-db "$CB/work/cvefixes_php.sqlite" --vul-root "$CB/vul" --only-language php "$@"
