#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Fetch the CI and infrastructure files of a seeded random sample of the repositories in repos.txt (transfer node).
# ``nohup bash iac_fetch.sh 1200 4 > fetch.log 2>&1 &``
set -u
N="${1:-1200}"; P="${2:-4}"
D=/scratch/bandari.ru/kestrix/iac
mkdir -p "$D/corpus"
python3 - "$D/repos.txt" "$N" > "$D/sample.txt" <<'PY'
import random, sys
names = sorted(set(open(sys.argv[1]).read().split()))
random.Random(20261023).shuffle(names)
print("\n".join(names[: int(sys.argv[2])]))
PY
xargs -P "$P" -n 1 bash "$D/iac_fetch_one.sh" < "$D/sample.txt"
echo FETCH_DONE
