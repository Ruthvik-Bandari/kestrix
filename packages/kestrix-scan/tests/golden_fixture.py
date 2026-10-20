# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A fixed project for the golden report test, and the normalization that makes a report comparable.

The golden files in ``golden/`` were written by the pydantic-based scanner before the move to
``kestrix_scan`` (Kestrix at commit e6144ab), so the test proves the JSON and SARIF output kept
their structure, keys and values.
"""

import json
import re
from pathlib import Path
from typing import Any

from code_samples import fake

FILES = {
    "app.py": (
        "import hashlib\nimport subprocess\n\n"
        "def run(cmd):\n    subprocess.run(cmd, shell=True)\n\n"
        "def digest(data):\n    return hashlib.md5(data).hexdigest()\n\n"
        "def calc(text):\n    return eval(text)  # kestrix: ignore[py.exec.eval]\n\n"
        "def safe(text):\n    return eval(text)  # kestrix: ignore[py.exec.eval] input is a fixed constant\n"
    ),
    "settings.env": f"GITHUB_TOKEN={fake('github_token')}\n",
    "lib/broken.py": "def f(:\n    pass\n",
}
BINARY = "blob.bin"


def build(root: Path) -> Path:
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / BINARY).write_bytes(b"\x00\x01binary")
    return root


def normalize_text(raw: str, root: str) -> str:
    """The JSON report text with the scan root and the duration replaced, byte for byte otherwise."""
    text = raw.replace(json.dumps(root), '"<root>"')
    return re.sub(r'"duration_ms": \d+', '"duration_ms": 0', text)


def normalize_sarif(data: dict[str, Any]) -> dict[str, Any]:
    run = data["runs"][0]
    run["originalUriBaseIds"]["SRCROOT"]["uri"] = "<root>"
    return data


def load(name: str) -> Any:
    return json.loads((Path(__file__).parent / "golden" / name).read_text(encoding="utf-8"))
