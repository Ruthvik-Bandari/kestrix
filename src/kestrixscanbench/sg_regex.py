# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Apply the security-guidance plugin's regex layer to every file under a directory.

Usage: ``python -I sg_regex.py PATTERNS_PY ROOT OUT_JSON``. ``PATTERNS_PY`` is the plugin's ``hooks/patterns.py``
(Apache-2.0) downloaded at a pinned commit; it is pure data, loaded here by path. Each file is checked the way the
plugin's PostToolUse hook checks a ``Write`` of that file's full content: a rule's ``path_filter`` gates it, then a
``path_check``, any of its ``substrings`` or its ``regex`` is a match. User-defined patterns are not loaded. The
output is a JSON list of ``{"path", "rule"}``; nothing from the scanned files is written.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules"}
MAX_BYTES = 1024 * 1024


def load_patterns(path: Path) -> list[dict[str, Any]]:
    spec = importlib.util.spec_from_file_location("sg_patterns", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    patterns: list[dict[str, Any]] = module.SECURITY_PATTERNS
    return patterns


def _call(predicate: Any, path: str) -> bool:
    try:
        return bool(predicate(path))
    except Exception:  # the plugin treats a failing predicate as no match
        return False


def matched_rules(patterns: list[dict[str, Any]], path: str, content: str) -> list[str]:
    rules = []
    for pattern in patterns:
        if "path_filter" in pattern and not _call(pattern["path_filter"], path):
            continue
        hit = "path_check" in pattern and _call(pattern["path_check"], path)
        hit = hit or (bool(content) and any(s in content for s in pattern.get("substrings", ())))
        hit = hit or (bool(content) and "regex" in pattern and re.search(pattern["regex"], content) is not None)
        if hit:
            rules.append(str(pattern["ruleName"]))
    return rules


def main(argv: list[str]) -> int:
    patterns = load_patterns(Path(argv[0]))
    root = Path(argv[1])
    out: list[dict[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            file = Path(dirpath) / name
            if file.stat().st_size > MAX_BYTES:
                continue
            rel = file.relative_to(root).as_posix()
            content = file.read_text(encoding="utf-8", errors="replace")
            out.extend({"path": rel, "rule": rule} for rule in matched_rules(patterns, rel, content))
    Path(argv[2]).write_text(json.dumps(out), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
