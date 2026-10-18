#!/bin/bash
# Creates an isolated data root for the AI-label sensitivity check: sources are symlinked
# read-only, the replay report and review files are copied, so nothing in the main root changes.
#   bash hpc/sensitivity_setup.sh
# then submit jobs with:  sbatch --export=ALL,KESTRIX_DATA=$SENS,KESTRIX_IGNORE_AI_LABELS=1 hpc/<job>
set -euo pipefail
MAIN="/scratch/$USER/kestrix/data"
SENS="/scratch/$USER/kestrix/data-sensitivity"
mkdir -p "$SENS/reports" "$SENS/review"
chmod 700 "$SENS/review"
for src in sigma otrf sigma-history.git manifests; do ln -sfn "$MAIN/$src" "$SENS/$src"; done
cp "$MAIN/reports/replay-positives.json" "$SENS/reports/"
cp -p "$MAIN/review/labels.csv" "$MAIN/review/candidates.jsonl" "$SENS/review/"
echo "sensitivity root ready: $SENS"
