#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Leave-one-out measurement of the Phase 2 changes on the PHP benchmark's dev split: scan each variant tree
# (hpc/codebench_php_variants.py makes them from the frozen FINAL tree) and write the paired change of FINAL_RUN
# against each (the final scanner against the final scanner without one change). Submits only; run on a login node.
#   KESTRIX_CODE=/scratch/$USER/kestrix/php/code3 bash hpc/codebench_php_ablate.sh FINAL_RUN VARIANT_DIR [VARIANT ...]
set -euo pipefail
FINAL="${1:?usage: bash hpc/codebench_php_ablate.sh FINAL_RUN VARIANT_DIR [VARIANT ...]}"
DIR="${2:?variant directory}"
shift 2
: "${KESTRIX_CODE:?set KESTRIX_CODE}"
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-php}"
LOGS="$KESTRIX_CODEBENCH/logs"
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
run="export KESTRIX_CODE=$KESTRIX_CODE; source $KESTRIX_CODE/hpc/codebench_env.sh; "
for name in "$@"; do
  scan=$(sb --parsable --account=aai6610.202610 --partition=short --mem=8G --time=01:00:00 --job-name="kx-php-lo-$name" \
    --output="$LOGS/%x-%j.out" --export=ALL \
    --wrap="$run export PYTHONPATH=$DIR/$name/packages/kestrix-scan/src:$KESTRIX_CODE/src:$KESTRIX_CODE; KESTRIX_CODEBENCH_SHA=$name; cb scan scan --root \$CB --tool kestrix --run lo-$name")
  cmp=$(sb --parsable --account=aai6610.202610 --partition=short --mem=16G --time=01:00:00 --job-name="kx-php-cmp-$name" \
    --output="$LOGS/%x-%j.out" --export=ALL --dependency=afterok:"$scan" \
    --wrap="$run cb compare compare --root \$CB --base-run $FINAL --run lo-$name --label php-lo-$name --split dev")
  echo "$name scan $scan compare $cmp" | tee -a "$LOGS/rounds.ids"
done
