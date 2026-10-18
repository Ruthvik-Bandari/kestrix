#!/bin/bash -l
#SBATCH --job-name=aegis-freeze
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Freezes the split once (benchmark/split-manifest.json is never overwritten). One-way: run only
# after review is final. Later variants/natural/evaluate runs use the frozen manifest by default.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
DATA="${AEGIS_DATA:-/scratch/$USER/aegis-sec/data}"
uv run --no-sync python -m aegisbench split --root "$DATA" --freeze
sha256sum "$DATA/benchmark/split-manifest.json"
