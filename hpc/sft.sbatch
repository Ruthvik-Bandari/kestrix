#!/bin/bash -l
#SBATCH --job-name=kestrix-sft
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Builds M1 training examples from the train and development cases (never test) into sft/.
set -euo pipefail
source "$HOME/kestrix/hpc/engine.sh"
uv run --no-sync python -m kestrixbench sft --root "$DATA" --es-url "$ES_URL"
