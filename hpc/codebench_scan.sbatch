#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-scan
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=03:00:00
#SBATCH --array=0-7
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%A_%a.out
# One array task per dev shard for one tool: sbatch --export=ALL,TOOL=kestrix,RUN=base hpc/codebench_scan.sbatch
# TOOL is kestrix, bandit or eslint (eslint runs on the cluster's Node module). Dev shards only; never the test split,
# except SPLIT=tuning (round-1 dev + the spent round-1 test; refused unless LOCKED_EVAL.json exists).
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/hpc/codebench_env.sh"
: "${TOOL:?set TOOL}" "${RUN:?set RUN}"
if [ "$TOOL" = eslint ]; then module load nodejs/v22.11.0; fi
"$HOME/kestrix/.venv/bin/python" -c 'import kestrix_scan; print("kestrix_scan from", kestrix_scan.__file__)'
cb "$TOOL $RUN shard $SLURM_ARRAY_TASK_ID" scan --root "$CB" --tool "$TOOL" --run "$RUN" --split "${SPLIT:-dev}" --shard "$SLURM_ARRAY_TASK_ID"
