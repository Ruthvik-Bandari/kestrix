#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-dev
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# Baseline metrics on dev for every feature set, same-era strata, miss and false-alarm causes, leakage
# controls: writes reports/mail-dev-metrics.json. Reads dev features only.
set -euo pipefail
source "$HOME/kestrix/hpc/mail_env.sh"
mb dev-metrics dev-metrics --root "$MB" "$@"
