# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""File and URL forensics: hashes, entropy, real file type, EXIF privacy and offline URL heuristics.

Nothing in this package executes an analysed file or contacts an analysed URL.
"""

from .analysis import analyze_file
from .url import analyze_url

__all__ = ["analyze_file", "analyze_url"]
