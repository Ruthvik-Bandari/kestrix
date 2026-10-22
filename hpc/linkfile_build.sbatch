#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-lf-build
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/linkfilebench/logs/%x-%j.out
# Offline. Usage: sbatch hpc/linkfile_build.sbatch link|file [extra build options]
# link: PhiUSIIL + Majestic -> filter, deduplicate, group, split. file: Govdocs threads -> hash, deduplicate by content,
# add the synthetic cases, split. Writes <root>/<kind>/work (private) and reports/build.json, split-manifest.json (counts).
set -euo pipefail
source "${KESTRIX_CODE:-$HOME/kestrix-linkfile}/hpc/linkfile_env.sh"
KIND="${1:?usage: sbatch hpc/linkfile_build.sbatch link|file}"
shift
lb "build-$KIND" build --root "$LB" --kind "$KIND" "$@"
ls -l "$LB/$KIND/work" "$LB/$KIND/reports"
