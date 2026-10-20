# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Copy the Kestrix demo project to a fresh directory and plant a fake GitHub token in it.

Usage: python3 docs/demo/setup_demo.py DEST

The token is assembled here at run time, so no token-shaped string is committed anywhere. It is
synthetic: it was never issued by GitHub and grants nothing. Standard library only.
"""

from __future__ import annotations

import shutil
import string
import sys
from pathlib import Path

SAMPLE = Path(__file__).resolve().parent / "sample-project"
ALPHABET = string.ascii_letters + string.digits


def fake_github_token() -> str:
    """A deterministic, high-entropy string in the shape of a GitHub token. Not a real credential."""
    body = "".join(ALPHABET[(i * 7 + i * i * 3 + 7) % len(ALPHABET)] for i in range(36))
    return "gh" + "p_" + body


def setup(dest: Path) -> Path:
    if dest.is_symlink() or (dest.exists() and any(dest.iterdir())):
        raise SystemExit(f"{dest} already exists and is not empty; choose a new directory")
    shutil.copytree(SAMPLE, dest, dirs_exist_ok=True)
    settings = f'"""Local settings for the demo. The token is fake and planted on purpose."""\n\nGITHUB_TOKEN = "{fake_github_token()}"\n'
    (dest / "settings_local.py").write_text(settings, encoding="utf-8")
    return dest


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: python3 docs/demo/setup_demo.py DEST\n")
        return 2
    dest = setup(Path(argv[1]).expanduser().resolve())
    sys.stdout.write(f"Demo project ready at {dest}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
