#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-learn
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=16G
#SBATCH --time=06:00:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# Learn non-negative L2 logistic-regression weights on dev with grouped cross-validation, for four
# leakage-aware feature sets: all (every finding, for contrast), content (no auth findings; the default),
# content_strict (also no header-era ids) and content_noera (also no id flagged era-sensitive by dev-metrics).
# Each runs with the false-alarm target applied to every ham source (default) and to pooled ham (_pooled).
# Needs reports/mail-dev-metrics.json. Writes reports/mail-weights-<set>[_pooled].json and mail-learn-<set>[_pooled].json.
# Extra arguments (for example --far-suspicious 0.03) apply to all runs.
set -euo pipefail
source "$HOME/kestrix/hpc/mail_env.sh"
for fs in all content content_strict content_noera; do
  mb "learn $fs" learn --root "$MB" --feature-set "$fs" "$@"
  mb "learn $fs pooled" learn --root "$MB" --feature-set "$fs" --far-basis pooled --output-suffix _pooled "$@"
done
ls -l "$MB/reports"
