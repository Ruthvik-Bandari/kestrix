#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Run on the transfer node (compute nodes have no internet; the transfer node is CentOS 7, so it
# uses a uv-managed Python and the standard-library-only acquire step, not the project venv):
#   ssh explorer-xfer 'cd ~/kestrix && bash -l research/hpc/detect/acquire.sh'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
module load git/2.19.0  # system git there is 1.8
DATA="/scratch/$USER/kestrix/data"
mkdir -p "$DATA" "/scratch/$USER/kestrix/logs"
PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixbench acquire --root "$DATA"
