#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-mail-smoke
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=00:40:00
#SBATCH --output=/scratch/%u/kestrix/mailbench/logs/%x-%j.out
# The whole chain on a few hundred messages under $MB/smoke (raw files come from $MB/raw): build, split,
# features, dev metrics and one learn. Never touches the locked test. Run research/hpc/mail/mail_acquire.sh first.
set -euo pipefail
source "$HOME/kestrix/research/hpc/mail/mail_env.sh"
S="$MB/smoke"
mb build   build   --root "$S" --raw "$MB" --shards 4 --limit 12 --enron-sample 100
for shard in 0 1 2 3; do mb "features-$shard" features --root "$S" --shards 4 --shard "$shard"; done
mb dev-metrics dev-metrics --root "$S" --shards 4 --bootstrap 50
mb learn   learn --root "$S" --shards 4 --feature-set content --folds 3 --bootstrap 50
ls -l "$S/reports"
