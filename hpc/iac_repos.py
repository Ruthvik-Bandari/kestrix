# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""List the public GitHub repositories the codebench pair files already mention (one ``owner/name`` per line).

Run on the cluster: ``python3 iac_repos.py /scratch/bandari.ru/kestrix > repos.txt``. Only repository names are read.
"""

import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
names: set[str] = set()
for pairs in sorted(root.glob("codebench*/work/pairs.jsonl")):
    with pairs.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            for repo in row.get("repos") or [row.get("group")]:
                if isinstance(repo, str) and repo.count("/") == 1:
                    names.add(repo)
print("\n".join(sorted(names)))
