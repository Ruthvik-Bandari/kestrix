#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=24G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%j.out
# Offline: unpack the downloaded list months, deduplicate, cap, split by list, add the synthetic cohort.
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/research/hpc/mail/modern_env.sh"
mm build build "$@"
