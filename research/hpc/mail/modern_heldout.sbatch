#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-modern-heldout
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/mailmodern/logs/%x-%j.out
# The one-time held-out measurement of the CURRENT rules on the held-out lists. Claims reports/LOCKED_EVAL.json
# (exclusive create) and refuses a second run. Run it once, after the dev-based proposals are written.
set -euo pipefail
source "/scratch/$USER/kestrix/mailmodern-code/research/hpc/mail/modern_env.sh"
mm heldout heldout "$@"
