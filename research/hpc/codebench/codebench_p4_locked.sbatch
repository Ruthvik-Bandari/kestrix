#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp4-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=24:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench-p4/logs/%x-%j.out
# THE ONE-TIME HELD-OUT RUN of the Phase 4 benchmark (Go, Java, Kotlin, C#, Ruby, ERB). Claims reports/LOCKED_EVAL.json
# (exclusive create; a second run is refused), scans the test split with kestrix-scan, gosec and opengrep and writes
# reports/codebench-locked-p4-v1.json. The claim file research/results/codebench/p4-heldout-claim.json was committed
# before this ran.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix/p4/code-q4 research/hpc/codebench/codebench_p4_locked.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-p4}"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
cb locked locked-test --root "$CB" --name p4-v1 --tools kestrix,gosec,opengrep --tool-run kestrix=q4 --tool-run gosec=gosec1 --tool-run opengrep=opengrep1
