#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-probe
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# Aggregate tag counts per cohort of dev messages (coarse properties and curated candidate terms; no text, hosts or
# addresses leave the job). Cohorts come from the dev verdicts of the run under --baseline-root.
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix}/hpc/mail_env.sh"
mb probe probe --root "$MB" --baseline-root "${BASELINE_ROOT:-$BASE_MB}" "$@"
