#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb2-prep
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=32G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench2/logs/%x-%j.out
# test2 (second held-out set), offline stages: STAGE=select (advisories and fix commits not in the existing data,
# from the fresh raw/ghsa checkout) or STAGE=build (filters, de-duplication, shards, manifests after the fetch).
#   sbatch --export=ALL,STAGE=select,KESTRIX_CODE=$HOME/kestrix-codebench2,KESTRIX_CODEBENCH=/scratch/$USER/kestrix/codebench2 research/hpc/codebench/codebench2_prep.sbatch [--allow-known-repos]
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench2}/research/hpc/codebench/codebench_env.sh"
: "${STAGE:?set STAGE=select or build}"
OLD="/scratch/$USER/kestrix/codebench"
cb "test2 $STAGE" "test2-$STAGE" --root "$CB" --old-root "$OLD" --vul-root "$VUL" "$@"
