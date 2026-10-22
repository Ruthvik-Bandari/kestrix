#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-cb-speed
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=8G
#SBATCH --time=05:00:00
#SBATCH --output=/scratch/%u/kestrix/codebench/logs/%x-%j.out
# Scanner speed on the dev files: every dev shard in turn on one core, two repetitions, for each code tree named in
# SPEED_TREES ("name=path ..."): the scanner comes from that tree, the benchmark code from KESTRIX_CODE. Writes scans/speed-NAME-rep/kestrix/*.report.json (seconds and files per shard).
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-codebench}/hpc/codebench_env.sh"
: "${SPEED_TREES:?set SPEED_TREES to 'name=path ...'}"
hostname
for rep in 1 2; do
  for entry in $SPEED_TREES; do
    name="${entry%%=*}"; tree="${entry#*=}"
    PYTHONPATH="$tree/packages/kestrix-scan/src:$CODE/src:$CODE" KESTRIX_CODEBENCH_SHA="$name" \
      "$HOME/kestrix/.venv/bin/python" -m kestrixcodebench scan --root "$CB" --tool kestrix --run "speed-$name-$rep"
  done
done
