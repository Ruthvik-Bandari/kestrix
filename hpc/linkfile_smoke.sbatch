#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-smoke
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=12G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%j.out
# Both chains on a few hundred items under $LB/smoke (raw files come from $LB/raw): build, split, dev features and
# dev metrics per kind. Never touches the locked test split's features. Run hpc/linkfile_acquire.sh first.
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/hpc/linkfile_env.sh"
S="$LB/smoke"
lb build-link build --root "$S" --raw-root "$LB" --kind link --limit 400 --majestic 400
for shard in $(seq 0 15); do lb "features-link-$shard" features --root "$S" --kind link --shard "$shard" --splits dev; done
lb dev-link dev-metrics --root "$S" --kind link --bootstrap 50
lb build-file build --root "$S" --raw-root "$LB" --kind file --limit 60
for shard in $(seq 0 19); do lb "features-file-$shard" features --root "$S" --raw-root "$LB" --kind file --shard "$shard" --splits dev; done
lb dev-file dev-metrics --root "$S" --kind file --bootstrap 50
ls -l "$S/link/reports" "$S/file/reports"
