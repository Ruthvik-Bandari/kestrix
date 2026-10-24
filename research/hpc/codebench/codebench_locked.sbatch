#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=12:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# THE ONE-TIME LOCKED TEST. Claims reports/LOCKED_EVAL.json (exclusive create, refuses a second run), scans the test
# split with every tool and writes reports/codebench-locked-NAME.json. Run it once, after the dev rounds are frozen:
#   sbatch research/hpc/codebench/codebench_locked.sbatch --name codebench-v1 --tool-run kestrix=FINAL --tool-run bandit=base --tool-run eslint=base
# The --tool-run labels name the dev runs used for the dry run of the scoring code (kestrix is rescanned on test).
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/research/hpc/codebench/codebench_env.sh"
module load nodejs/v22.11.0
cb locked locked-test --root "$CB" "$@"
