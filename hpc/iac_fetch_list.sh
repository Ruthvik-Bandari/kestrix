#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Fetch the CI and infrastructure files of the repositories in iac_extra_repos.txt (transfer node): the lines before
# "# fixtures" go to corpus-extra, the lines after it to corpus-fixtures. ``nohup bash iac_fetch_list.sh &``
set -u
D=/scratch/bandari.ru/kestrix/iac
mkdir -p "$D/corpus-extra" "$D/corpus-fixtures"
awk '/^# fixtures/{f=1;next} /^#/{next} NF{print (f?"fix ":"ext ") $0}' "$D/code/hpc/iac_extra_repos.txt" > "$D/extra-list.txt"
while read -r kind repo; do
  if [ "$kind" = fix ]; then IAC_OUT=$D/corpus-fixtures; else IAC_OUT=$D/corpus-extra; fi
  export IAC_OUT
  echo "$repo"
done < "$D/extra-list.txt" | xargs -P 4 -I{} bash -c 'repo={}; d=/scratch/bandari.ru/kestrix/iac; if grep -q "^fix $repo\$" "$d/extra-list.txt"; then IAC_OUT=$d/corpus-fixtures; else IAC_OUT=$d/corpus-extra; fi; mkdir -p $IAC_OUT; IAC_OUT=$IAC_OUT bash $d/code/hpc/iac_fetch_one.sh $repo'
echo EXTRA_DONE
