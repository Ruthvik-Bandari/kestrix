#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Transfer node only. Downloads the C6 student base model at its pinned revision (weights, config and
# tokenizer only; no repository code) and writes MANIFEST.sha256:
#   ssh explorer-xfer 'cd ~/kestrix && setsid nohup bash -l research/hpc/vul/fetch_vul_student_model.sh \
#     > /scratch/$USER/kestrix/vul/logs/fetch-student-model.log 2>&1 < /dev/null &'
# microsoft/unixcoder-base is Apache-2.0 (checked 2026-10-20: Hugging Face license tag and model card).
# The teacher (Qwen2.5-Coder-7B-Instruct) is fetched by research/hpc/detect/fetch_model.sh. Keep the revision in sync with
# STUDENT_REVISION in src/kestrixvul/train.py (a test checks this).
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
MODELS="/scratch/$USER/kestrix/models"
spec="microsoft/unixcoder-base@5604afdc964f6c53782a6813140ade5216b99006"
repo="${spec%@*}"; rev="${spec#*@}"
dest="$MODELS/$(basename "$repo")@$rev"
if [ -f "$dest/MANIFEST.sha256" ]; then echo "present: $dest"; exit 0; fi
mkdir -p "$dest"
uv run --no-project --python 3.12 --with 'huggingface_hub>=0.25,<1' python - "$repo" "$rev" "$dest" <<'PY'
import sys
from huggingface_hub import snapshot_download
repo, rev, dest = sys.argv[1:4]
snapshot_download(repo, revision=rev, local_dir=dest, max_workers=4,
                  allow_patterns=["*.json", "*.safetensors", "pytorch_model.bin", "*.txt", "LICENSE", "tokenizer*", "vocab*", "merges*"])
PY
(cd "$dest" && find . -type f ! -name MANIFEST.sha256 ! -path './.cache/*' -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
echo "model ready: $dest ($(wc -l < "$dest/MANIFEST.sha256") files)"
