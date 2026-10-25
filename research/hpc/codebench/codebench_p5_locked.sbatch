#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cbp5-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=24:00:00
#SBATCH --output=/scratch/%u/kestrix-sys/codebench-p5/logs/%x-%j.out
# THE ONE-TIME HELD-OUT RUN of the Phase 5 benchmark (C, C++, Rust, Swift). Claims reports/LOCKED_EVAL.json (exclusive
# create; a second run is refused), scans the test split with kestrix-scan, flawfinder and opengrep-sys and writes
# reports/codebench-locked-p5-v1.json. The claim file research/results/codebench/p5-heldout-claim.json was committed
# before this ran.
#   sbatch --export=ALL,KESTRIX_CODE=/scratch/$USER/kestrix-sys/code-final research/hpc/codebench/codebench_p5_locked.sbatch
set -euo pipefail
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix-sys/codebench-p5}"
source "${KESTRIX_CODE:?set KESTRIX_CODE}/research/hpc/codebench/codebench_env.sh"
cb locked locked-test --root "$CB" --name p5-v1 --tools kestrix,flawfinder,opengrep-sys --tool-run kestrix=r1 --tool-run flawfinder=ff1 --tool-run opengrep-sys=og1
