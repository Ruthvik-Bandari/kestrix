#!/bin/bash -l
#SBATCH --job-name=aegis-qc
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Offline: verifies manifests and writes aggregate QC reports. Run hpc/acquire.sh first.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
DATA="${AEGIS_DATA:-/scratch/$USER/aegis-sec/data}"  # override for a separate run, e.g. the sensitivity check
uv run --no-sync python -m aegisbench qc --root "$DATA"
ls -l "$DATA/reports"
