#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-locked
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# The one-time locked test evaluation: baselines and the learned weights on the test split. Claims
# reports/LOCKED_EVAL.json (exclusive create) and refuses a second run. Choose the weights first; pass them:
#   sbatch research/hpc/mail/mail_locked.sbatch --name mail-v1 --weights $MB/reports/mail-weights-content.json
# Writes reports/mail-locked-<name>.json.
set -euo pipefail
source "$HOME/kestrix/research/hpc/mail/mail_env.sh"
mb locked locked-test --root "$MB" "$@"
