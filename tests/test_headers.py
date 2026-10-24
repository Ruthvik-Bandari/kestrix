# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Every tracked source file carries the SPDX copyright and license header."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [
    "src/*.py",
    "tests/*.py",
    "scripts/*.py",
    "research/*.py",
    "packages/*.py",
    "packages/*.toml",
    "hpc/*.sh",
    "hpc/*.sbatch",
    "frontend/src/*.ts",
    "frontend/src/*.tsx",
]


def test_every_source_file_has_the_spdx_header():
    names = subprocess.run(
        ["git", "ls-files", *PATTERNS], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    # A tracked file deleted in the working tree is not a source file any more.
    present = [name for name in names if (ROOT / name).is_file()]
    missing = [
        name
        for name in present
        if "SPDX-FileCopyrightText: 2026 Ruthvik Bandari" not in (head := (ROOT / name).read_text()[:400])
        or "SPDX-License-Identifier: Apache-2.0" not in head
    ]
    assert present and missing == []
