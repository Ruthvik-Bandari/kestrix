#!/bin/bash -l
#SBATCH --job-name=kestrix-evaluate
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Scores a repair system on benchmark/cases (train + development) on a job-scoped pinned engine:
#   sbatch hpc/evaluate.sbatch b0
# The locked test split is evaluated once, after a system is chosen: sbatch hpc/evaluate.sbatch b0 --locked
set -euo pipefail
source "$HOME/kestrix/hpc/engine.sh"
uv run --no-sync python -m kestrixbench evaluate --root "$DATA" --es-url "$ES_URL" --system "${1:-b0}" "${@:2}"
