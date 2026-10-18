#!/bin/bash -l
# Run on the transfer node: ssh explorer-xfer 'cd ~/kestrix && bash -l hpc/fetch_history.sh'
# Full-history bare clone of SigmaHQ for natural-fault mining (about 50 MB). Mining reads history
# only up to the pinned commit, so later upstream commits never enter the benchmark.
set -euo pipefail
module load git/2.19.0  # system git there is 1.8
PINNED=552f3fee420ef232a8e5790c4fae591847e32347  # keep in sync with src/kestrixbench/sources.py (a test checks)
DEST="/scratch/$USER/kestrix/data/sigma-history.git"
if [ -d "$DEST" ]; then
  git --git-dir="$DEST" fetch -q origin '+refs/heads/*:refs/heads/*'
else
  git clone -q --bare https://github.com/SigmaHQ/sigma.git "$DEST"
fi
git --git-dir="$DEST" cat-file -e "$PINNED^{commit}"
echo "history ready: $DEST (pinned $PINNED present)"
