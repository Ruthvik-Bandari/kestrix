#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-diag
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%j.out
# Dev-only aggregate diagnostics of the false-alarm causes (counts of coarse categories, never text).
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/research/hpc/mail/modern_env.sh"
mm diag diag "$@"
