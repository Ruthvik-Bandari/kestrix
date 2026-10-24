#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-features
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=6G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%A_%a.out
# One array task per shard: kestrix.forensics analyzer over every item (offline), writing features/ only (finding ids,
# severities, type, shape counts; no URL, name or content). Usage (links 0-15, files 0-19):
#   sbatch --array=0-15 research/hpc/linkfile/linkfile_features.sbatch link dev
# The second argument is the split list; rule rounds and baselines use dev, the locked test run uses test.
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/research/hpc/linkfile/linkfile_env.sh"
KIND="${1:?usage: sbatch --array=... research/hpc/linkfile/linkfile_features.sbatch link|file dev|test|dev,test}"
SPLITS="${2:?split list}"
lb "features-$KIND-$SLURM_ARRAY_TASK_ID" features --root "$LB" --kind "$KIND" --shard "$SLURM_ARRAY_TASK_ID" --splits "$SPLITS"
