# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-78): CLI backup helper that builds a tar command from argv."""

import os
import sys


def backup(folder: str) -> int:
    return os.system("tar czf /var/backups/site.tgz " + folder)


if __name__ == "__main__":
    raise SystemExit(backup(sys.argv[1]))
