#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-probe
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%j.out
# Counts of curated tags (hosting platforms, host shapes, content classes of the first bytes) per cohort of dev items
# under the shipped rules: reports/<kind>-probe.json. Reads raw URLs or files of dev items on the cluster only; the
# report holds counts, never a URL, host or file name. Usage: sbatch hpc/linkfile_probe.sbatch link|file
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/hpc/linkfile_env.sh"
KIND="${1:?usage: sbatch hpc/linkfile_probe.sbatch link|file}"
lb "probe-$KIND" probe --root "$LB" --kind "$KIND"
