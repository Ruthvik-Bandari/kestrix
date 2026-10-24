#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-report
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%j.out
# Dev aggregates (reports/modern-dev.json).
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/research/hpc/mail/modern_env.sh"
mm report report "$@"
