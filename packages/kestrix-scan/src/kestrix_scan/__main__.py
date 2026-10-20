# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrix_scan``: the same as the ``kestrix-scan`` command."""

import sys

from .cli import main

sys.exit(main(prog="python -m kestrix_scan"))
