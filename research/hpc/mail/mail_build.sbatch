#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=24G
#SBATCH --time=06:00:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# Offline. Unpack, drop what the analyzer rejects, deduplicate, label, group, then the dev/test split.
# Writes work/ (raw messages, private) and reports/build.json, reports/split-manifest.json (counts only).
# Run research/hpc/mail/mail_acquire.sh first.
set -euo pipefail
source "$HOME/kestrix/research/hpc/mail/mail_env.sh"
mb build build --root "$MB" "$@"
ls -l "$MB/work" "$MB/reports"
