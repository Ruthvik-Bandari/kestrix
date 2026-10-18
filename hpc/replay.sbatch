#!/bin/bash -l
#SBATCH --job-name=kestrix-replay
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Replays every supported Sigma rule against the SigmaHQ regression and OTRF pools on a job-scoped
# pinned Elasticsearch. Run hpc/acquire.sh and hpc/fetch_engine.sh first.
set -euo pipefail
source "$HOME/kestrix/hpc/engine.sh"
uv run --no-sync python -m kestrixbench replay --root "$DATA" --es-url "$ES_URL"
