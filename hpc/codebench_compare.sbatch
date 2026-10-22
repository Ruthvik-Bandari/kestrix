#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-compare
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# Paired change between two kestrix runs on dev (the same repository resamples, so each difference has an interval):
#   sbatch hpc/codebench_compare.sbatch --base-run base --run r1-v1 --label r1-v1
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/hpc/codebench_env.sh"
cb compare compare --root "$CB" "$@"
