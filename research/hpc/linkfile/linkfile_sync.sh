#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Run on the laptop from the worktree: copy the code the link and file benchmark needs to the cluster.
#   bash research/hpc/linkfile/linkfile_sync.sh [DEST] [HOST]       DEST defaults to kestrix-linkfile (relative to the cluster home)
#   BASELINE=1 bash research/hpc/linkfile/linkfile_sync.sh kestrix-linkfile-base      the committed HEAD instead of the working tree
#   PARTIAL=1 bash research/hpc/linkfile/linkfile_sync.sh kestrix-linkfile-rounds/NAME  only src/kestrix/forensics, into a DEST that
#                                                  already holds a full copy (rule rounds: `cp -r` it on the cluster first)
# Writes DEST/LINKFILEBENCH_SHA: HEAD plus a hash of the checker's rule code (src/kestrix/forensics and core), so only a
# rule change alters it and the same rules always give the same value: dev and test features must come from the same
# rules. ~/kestrix/GIT_SHA is never touched.
set -euo pipefail
cd "$(dirname "$0")/../../.."
DEST="${1:-kestrix-linkfile}"
HOST="${2:-explorer}"
PATHS="src packages/kestrix-scan/src research/hpc pyproject.toml"
[ "${PARTIAL:-}" = 1 ] && PATHS="src/kestrix/forensics"
HASHED="src/kestrix/forensics src/kestrix/core"
TMP="$(mktemp)"
CHECK="$(mktemp -d)"
trap 'rm -rf "$TMP" "$CHECK"' EXIT
# shellcheck disable=SC2086
if [ "${BASELINE:-}" = 1 ]; then
  git archive --format=tar.gz -o "$TMP" HEAD $PATHS
  git archive HEAD $HASHED | tar x -C "$CHECK"
else
  COPYFILE_DISABLE=1 tar czf "$TMP" --no-xattrs --exclude='__pycache__' --exclude='*.pyc' $PATHS
  tar cf - --exclude='__pycache__' --exclude='*.pyc' $HASHED | tar x -C "$CHECK"
fi
# shellcheck disable=SC2086
HASH=$(cd "$CHECK" && find $HASHED -type f -name '*.py' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-12)
SHA="$(git rev-parse --short HEAD)+worktree-$HASH"
# A temporary file sent with scp, not a pipe into `tar xzf -`: that stalled on this cluster.
REMOTE="/tmp/linkfile-sync-$$.tgz"
scp -q "$TMP" "$HOST:$REMOTE"
ssh -n "$HOST" "mkdir -p '$DEST' && cd '$DEST' && tar xzf '$REMOTE' && rm -f '$REMOTE' && echo '$SHA' > LINKFILEBENCH_SHA"
echo "$DEST $SHA"
