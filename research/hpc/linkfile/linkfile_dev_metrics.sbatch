#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-dev
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%j.out
# Dev metrics with grouped bootstrap intervals, error analysis and leakage controls: writes
# reports/<kind>-dev-metrics.json. Reads dev features only. Usage: sbatch research/hpc/linkfile/linkfile_dev_metrics.sbatch link|file
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/research/hpc/linkfile/linkfile_env.sh"
KIND="${1:?usage: sbatch research/hpc/linkfile/linkfile_dev_metrics.sbatch link|file}"
shift
lb "dev-metrics-$KIND" dev-metrics --root "$LB" --kind "$KIND" "$@"
