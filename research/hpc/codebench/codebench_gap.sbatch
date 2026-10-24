#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-gap
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# Pairs Bandit detects and kestrix does not, by Bandit test id (aggregates only: reports/codebench-gap-LABEL.json):
#   sbatch research/hpc/codebench/codebench_gap.sbatch --split tuning --label r3-gap --tool-run kestrix=r3-t0 --tool-run bandit=bandit-tuning
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/research/hpc/codebench/codebench_env.sh"
cb gap bandit-gap --root "$CB" "$@"
