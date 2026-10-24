#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%j.out
# The one-time locked test evaluation of one kind. Claims <root>/<kind>/reports/LOCKED_EVAL.json (exclusive create) and
# refuses a second run. Submitted with its test features by research/hpc/linkfile/linkfile_locked.sh; not run by any other script.
# Usage: sbatch research/hpc/linkfile/linkfile_locked.sbatch link|file --name linkfile-v1 [--baseline-root DIR]
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/research/hpc/linkfile/linkfile_env.sh"
KIND="${1:?usage: sbatch research/hpc/linkfile/linkfile_locked.sbatch link|file --name NAME}"
shift
lb "locked-$KIND" locked-test --root "$LB" --kind "$KIND" "$@"
