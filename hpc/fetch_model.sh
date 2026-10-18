#!/bin/bash -l
# Run on the transfer node: ssh explorer-xfer 'cd ~/kestrix && bash -l hpc/fetch_model.sh'
# Downloads the B2 base model at the revision pinned in src/kestrixbench/b2.py (weights, config and
# tokenizer only; no repository code) and writes a SHA-256 manifest next to it.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
# Keep in sync with MODEL_REPO / MODEL_REVISION in src/kestrixbench/b2.py (a test checks this).
REPO=Qwen/Qwen2.5-Coder-7B-Instruct
REV=c03e6d358207e414f1eca0bb1891e29f1db0e242
DEST="/scratch/$USER/kestrix/models/$(basename "$REPO")@$REV"
mkdir -p "$DEST"
uv run --no-project --python 3.12 --with 'huggingface_hub>=0.25,<1' python - "$REPO" "$REV" "$DEST" <<'PY'
import sys
from huggingface_hub import snapshot_download
repo, rev, dest = sys.argv[1:4]
snapshot_download(repo, revision=rev, local_dir=dest,
                  allow_patterns=["*.json", "*.safetensors", "*.txt", "LICENSE", "tokenizer*", "vocab*", "merges*"])
PY
(cd "$DEST" && find . -type f ! -name MANIFEST.sha256 ! -path './.cache/*' -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
echo "model ready: $DEST ($(wc -l < "$DEST/MANIFEST.sha256") files)"
