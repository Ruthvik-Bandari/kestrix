#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Offline. Stage "candidates" (default): labels, dedup and the public repository list for the
# license lookup. Then run `licenses-fetch` on the owner's machine (docs/data/vul/README.md), copy
# the table to $VUL/licenses/fetched.csv, and run stage "split": licenses-import and split.
# No model is trained and nothing is evaluated. Run research/hpc/vul/vul_qc.sbatch first.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
umask 077
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
run() { /usr/bin/time -f "$1: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul "$@" --root "$VUL"; }
case "${1:-candidates}" in
  candidates)
    run labels
    run dedup
    run licenses-export
    ;;
  split)
    run licenses-import --table "$VUL/licenses/fetched.csv"
    run split
    ;;
  *) echo "usage: sbatch research/hpc/vul/vul_build.sbatch [candidates|split]" >&2; exit 2 ;;
esac
ls -l "$VUL/work" "$VUL/reports"
