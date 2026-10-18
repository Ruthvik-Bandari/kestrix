#!/bin/bash -l
#SBATCH --job-name=aegis-review-split
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=1
#SBATCH --mem=4G
#SBATCH --time=00:30:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# After hpc/replay.sbatch: writes the private OTRF review sheet (never overwrites labels.csv),
# reports review progress (counts only) and writes the split preview. Freezing is a separate,
# deliberate step: `python -m aegisbench split --freeze --root ...`.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
DATA="${AEGIS_DATA:-/scratch/$USER/aegis-sec/data}"  # override for a separate run, e.g. the sensitivity check
uv run --no-sync python -m aegisbench review-sheet --root "$DATA"
uv run --no-sync python -m aegisbench review-status --root "$DATA" || true  # unreviewed rows are expected at first
uv run --no-sync python -m aegisbench split --root "$DATA"
