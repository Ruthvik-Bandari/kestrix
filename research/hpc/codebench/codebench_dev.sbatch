#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-dev
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# Dev metrics with repository-bootstrap intervals: writes reports/codebench-dev-LABEL.json. Reads dev findings only.
#   sbatch research/hpc/codebench/codebench_dev.sbatch --label r1-c1 --tool-run kestrix=r1-c1 --tool-run bandit=base --tool-run eslint=base
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/research/hpc/codebench/codebench_env.sh"
cb dev-metrics dev-metrics --root "$CB" "$@"
