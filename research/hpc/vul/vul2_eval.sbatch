#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul2-eval
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/vul2/logs/%x-%j.out
# Round-2 evaluation. Validation report (calibration split; no held-out data):
#   sbatch research/hpc/vul/vul2_eval.sbatch --name val-r2 --zero-shot --ensemble --teacher-run ... --student-run ...
# The one-time test-v2 evaluation (claims reports/LOCKED_EVAL_TEST2.json, refuses a second time):
#   sbatch research/hpc/vul/vul2_eval.sbatch --split test2 --locked --name test2-r2 --zero-shot --ensemble --teacher-run ... [--teacher-run c6-teacher]
set -euo pipefail
source "${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}/research/hpc/vul/vul2_env.sh"
$PY -m kestrixvul.evaluate --root "$VUL2" "$@"
