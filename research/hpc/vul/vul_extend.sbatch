#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-extend
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# Offline. Extends the C5 pool without touching the frozen test split (docs/data/vul/README.md):
#   targets  GHSA fix commits not in CVEfixes or MoreFixes, plus the pool commits (negatives)
#            -> then run research/hpc/vul/vul_mine.sh on the transfer node
#   extract  functions and PrimeVul labels of the fetched commits, dedup-extend, the list of new
#            repositories for the local license lookup (licenses/repos-new.txt), split manifest v2,
#            negatives and the audit packets of the new strata (research/hpc/vul/vul_audit.sbatch reviews them)
#   split    licenses-merge (licenses/fetched-new.csv), then split-extend and negatives again
#   audit    split-extend once more, after research/hpc/vul/vul_audit.sbatch wrote reports/audit.json
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
export PYTHONPATH="$HOME/kestrix/packages/kestrix-scan/src"
umask 077
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
run() { /usr/bin/time -f "$1: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul "$@" --root "$VUL"; }
case "${1:-}" in
  targets) run mine-targets ;;
  extract)
    run mine-extract
    run dedup-extend
    run licenses-export-new
    run split-extend
    run negatives
    run split-extend
    run audit-sample
    ;;
  split)
    run licenses-merge --table "$VUL/licenses/fetched-new.csv"
    run split-extend
    run negatives
    run split-extend
    ;;
  audit) run split-extend ;;
  *) echo "usage: sbatch research/hpc/vul/vul_extend.sbatch targets|extract|split|audit" >&2; exit 2 ;;
esac
ls -l "$VUL/work" "$VUL/reports"
