#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbphp-corpus
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-php/logs/%x-%j.out
# Findings per KLOC of the PHP and SQL rules on PHP and SQL files no CVE fix touched: the third-party PHP libraries that the
# Psalm install pulled in (Composer packages, under /scratch/$USER/kestrix/php/psalm/vendor). LABEL names the report.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/php/code4,LABEL=final research/hpc/codebench/codebench_php_corpus.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-php}"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
: "${LABEL:?set LABEL}"
cb "php-corpus $LABEL" php-corpus --root "$CB" --label "$LABEL" --corpus-dir "/scratch/$USER/kestrix/php/psalm/vendor"
