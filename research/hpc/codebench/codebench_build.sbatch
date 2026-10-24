#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# Build the file-pair benchmark from kestrixvul's CVEfixes working database and mined advisory commits (offline):
# filters, de-duplication, the dev/test split and the files under $CB/files. Writes reports/split-manifest.json.
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/research/hpc/codebench/codebench_env.sh"
cb build build --root "$CB" --cvefixes-db "$VUL/work/cvefixes.sqlite" --vul-root "$VUL" "$@"
