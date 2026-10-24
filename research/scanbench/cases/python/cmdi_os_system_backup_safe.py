# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-78): CLI backup helper using an argument list."""

import subprocess
import sys


def backup(folder: str) -> int:
    return subprocess.run(["tar", "czf", "/var/backups/site.tgz", "--", folder], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(backup(sys.argv[1]))
