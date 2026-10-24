#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-variants-report
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%j.out
# Aggregates the variant verdicts (reports/modern-variants.json). Dev only.
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/hpc/modern_env.sh"
mm variants-report variants-report
