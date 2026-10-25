#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Leave-one-out measurement of the Phase 4 changes on the Phase 4 benchmark's dev split. Two kinds of variant:
#   tree:NAME     scan the tree research/hpc/codebench/codebench_p4_variants.py made in VARIANT_DIR/NAME, then compare;
#   drop:RULE_ID  copy the FINAL_RUN findings without that rule (no rescan), then compare.
# Each writes reports/codebench-compare-p4-lo-NAME.json: the final scanner against the final scanner without one change.
#   KESTRIX_CODE=/scratch/$USER/kestrix/p4/code bash research/hpc/codebench/codebench_p4_ablate.sh FINAL_RUN VARIANT_DIR tree:noBuilt drop:go.ssrf.request ...
set -euo pipefail
FINAL="${1:?usage: bash research/hpc/codebench/codebench_p4_ablate.sh FINAL_RUN VARIANT_DIR VARIANT ...}"
DIR="${2:?variant directory}"
shift 2
: "${KESTRIX_CODE:?set KESTRIX_CODE}"
export KESTRIX_CODEBENCH="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench-p4}"
LOGS="$KESTRIX_CODEBENCH/logs"
sb() { local out; for _ in 1 2 3 4 5 6; do if out=$(sbatch "$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 10; done; return 1; }
run="export KESTRIX_CODE=$KESTRIX_CODE; source $KESTRIX_CODE/research/hpc/codebench/codebench_env.sh; "
common=(--account=aai6610.202610 --partition=short --export=ALL --output="$LOGS/%x-%j.out")
for item in "$@"; do
  kind="${item%%:*}"; name="${item#*:}"; label="${name//./_}"
  if [ "$kind" = tree ]; then
    first=$(sb --parsable "${common[@]}" --mem=8G --time=01:00:00 --job-name="kx-p4-lo-$label" \
      --wrap="$run export PYTHONPATH=$DIR/$name/packages/kestrix-scan/src:$KESTRIX_CODE/src:$KESTRIX_CODE; KESTRIX_CODEBENCH_SHA=$name; cb scan scan --root \$CB --tool kestrix --run lo-$label")
  else
    first=$(sb --parsable "${common[@]}" --mem=4G --time=00:20:00 --job-name="kx-p4-drop-$label" \
      --wrap="$run \$HOME/kestrix/.venv/bin/python -c 'import json,shutil,sys,pathlib; s=pathlib.Path(sys.argv[1])/\"scans\"; src=s/sys.argv[2]/\"kestrix\"; dst=s/(\"lo-\"+sys.argv[4])/\"kestrix\"; dst.mkdir(parents=True,exist_ok=True); [ (dst/f.name).write_text(\"\".join(l for l in f.open() if json.loads(l)[\"r\"]!=sys.argv[3])) for f in src.glob(\"*.findings.jsonl\") ]; [shutil.copy(f, dst/f.name) for f in src.glob(\"*.report.json\")]' \$CB $FINAL $name $label")
  fi
  cmp=$(sb --parsable "${common[@]}" --mem=16G --time=01:00:00 --job-name="kx-p4-cmp-$label" --dependency=afterok:"$first" \
    --wrap="$run cb compare compare --root \$CB --base-run $FINAL --run lo-$label --label p4-lo-$label --split dev")
  echo "$item first $first compare $cmp" | tee -a "$LOGS/rounds.ids"
done
