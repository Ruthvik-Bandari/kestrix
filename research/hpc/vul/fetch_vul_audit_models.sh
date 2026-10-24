#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Transfer node only. Downloads the two open-weight label-audit reviewers at pinned revisions
# (weights, config and tokenizer only; no repository code) and writes MANIFEST.sha256 into each:
#   ssh explorer-xfer 'cd ~/kestrix && setsid nohup bash -l research/hpc/vul/fetch_vul_audit_models.sh \
#     > /scratch/$USER/kestrix/vul/logs/fetch-audit-models.log 2>&1 < /dev/null &'
# Both are Apache-2.0 on Hugging Face (checked 2026-10-20, license tag and model card). Keep the
# revisions in sync with REVIEWERS in src/kestrixvul/audit_llm.py (a test checks this).
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
MODELS="/scratch/$USER/kestrix/models"
for spec in \
  "Qwen/Qwen2.5-Coder-32B-Instruct@381fc969f78efac66bc87ff7ddeadb7e73c218a7" \
  "ibm-granite/granite-34b-code-instruct-8k@4bdfb589ebd261be0942a00dd239175d9d65bc47"; do
  repo="${spec%@*}"; rev="${spec#*@}"
  dest="$MODELS/$(basename "$repo")@$rev"
  if [ -f "$dest/MANIFEST.sha256" ]; then echo "present: $dest"; continue; fi
  mkdir -p "$dest"
  uv run --no-project --python 3.12 --with 'huggingface_hub>=0.25,<1' python - "$repo" "$rev" "$dest" <<'PY'
import sys
from huggingface_hub import snapshot_download
repo, rev, dest = sys.argv[1:4]
snapshot_download(repo, revision=rev, local_dir=dest, max_workers=4,
                  allow_patterns=["*.json", "*.safetensors", "*.txt", "LICENSE", "tokenizer*", "vocab*", "merges*"])
PY
  (cd "$dest" && find . -type f ! -name MANIFEST.sha256 ! -path './.cache/*' -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
  echo "model ready: $dest ($(wc -l < "$dest/MANIFEST.sha256") files)"
done
echo "all audit models ready"
