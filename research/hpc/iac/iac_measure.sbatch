#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-iac-measure
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/iac/logs/%x-%j.out
# False alarms per KLOC of the Phase 3 rules on real public CI and infrastructure files, and agreement with zizmor,
# hadolint and checkov. The scanner has no dependencies, so it runs from the synced source tree with the uv Python.
#   sbatch --export=ALL,LABEL=final research/hpc/iac/iac_measure.sbatch
# The code is synced to /scratch/$USER/kestrix/iac/code (the home quota is full); KESTRIX_IAC_CODE overrides it.
set -euo pipefail
D=/scratch/$USER/kestrix/iac
mkdir -p "$D/logs" "$D/reports"
PY=/home/bandari.ru/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu/bin/python3.12
CODE="${KESTRIX_IAC_CODE:-/scratch/$USER/kestrix/iac/code}"
export PYTHONPATH="$CODE/packages/kestrix-scan/src"
: "${LABEL:?set LABEL}"
"$PY" -I -c "import sys; sys.path.insert(0, '$PYTHONPATH'); import kestrix_scan; print(kestrix_scan.__file__)"
"$PY" "$CODE/research/hpc/iac/iac_measure.py" --corpus "main=$D/corpus" --corpus "extra=$D/corpus-extra" --corpus "fixtures=$D/corpus-fixtures" --tools "$D/tools" --out "$D/reports/$LABEL" ${NO_TOOLS:+--no-tools} ${ONLY_TOOL:+--only-tool $ONLY_TOOL}
