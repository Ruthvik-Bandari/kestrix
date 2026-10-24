#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Fetch only the CI and infrastructure files of one public repository's default branch: the source tarball from
# codeload.github.com is streamed through tar, which keeps just the matching paths, into $OUT/<owner>__<name>/.
# Runs on the transfer node (its git is too old for partial clones): ``iac_fetch_one.sh owner/name``.
# The tarball's top directory name (repo-<ref>) is recorded in $OUT/<owner>__<name>.ref. No credentials, nothing executed.
set -u
repo="$1"
OUT="${IAC_OUT:-/scratch/bandari.ru/kestrix/iac/corpus}"
slug="${repo/\//__}"
[ -e "$OUT/$slug.done" ] && exit 0
tmp=$(mktemp -d /scratch/bandari.ru/kestrix/iac/tmp.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
if ! timeout 240 curl -sSfL --max-time 230 "https://codeload.github.com/$repo/tar.gz/HEAD" 2>/dev/null \
    | tar -xz -C "$tmp" --wildcards --exclude='*/node_modules/*' --exclude='*/vendor/*' --exclude='*/third_party/*' \
        '*/.github/workflows/*.yml' '*/.github/workflows/*.yaml' '*/action.yml' '*/action.yaml' '*/Dockerfile*' '*.Dockerfile' \
        '*/Containerfile*' '*.tf' '*.sh' '*.bash' '*.yml' '*.yaml' 2>/dev/null; then
  if [ -z "$(ls -A "$tmp" 2>/dev/null)" ]; then echo "$repo" >> "$OUT/failed.txt"; touch "$OUT/$slug.done"; exit 0; fi
fi
top=$(ls "$tmp" | head -1)
[ -n "$top" ] || { echo "$repo" >> "$OUT/failed.txt"; touch "$OUT/$slug.done"; exit 0; }
echo "$top" > "$OUT/$slug.ref"
mkdir -p "$OUT/$slug"
(cd "$tmp/$top" && find . -type f | head -400 | cpio -pdm "$OUT/$slug" 2>/dev/null)
touch "$OUT/$slug.done"
