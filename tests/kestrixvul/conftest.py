# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""A tiny synthetic vul data root: split manifest v2, negatives, filters and licenses (no real code)."""

import json
from pathlib import Path

import pytest

VULN = "def run{n}(cmd):\n    import subprocess\n    return subprocess.call(cmd, shell=True)\n"
PATCHED = "def run{n}(cmd):\n    import subprocess, shlex\n    return subprocess.call(shlex.split(cmd))\n"
NEG = "def helper{n}(x):\n    y = x + {n}\n    return y * 2\n"

# (id, split, repo, license class, has patch)
RECORDS = [
    ("tr1", "train", "github.com/o/a", "permissive", True),
    ("tr2", "train", "github.com/o/a", "permissive", True),
    ("tr3", "train", "github.com/o/b", "copyleft", True),
    ("tr4", "train", "github.com/o/c", "permissive", False),
    ("dv1", "dev", "github.com/o/d", "permissive", True),
    ("dv2", "dev", "github.com/o/e", "permissive", True),
    ("dv3", "dev", "github.com/o/e", "copyleft", True),
    ("te1", "test", "github.com/o/t", "permissive", True),
    ("tx1", "test_extension", "github.com/o/x", "permissive", True),
]
NEGATIVES = {"train": 20, "dev": 12, "test": 6, "test_extension": 4}
NEG_REPOS = {
    "train": ["github.com/o/a", "github.com/o/b"],
    "dev": ["github.com/o/d", "github.com/o/e"],
    "test": ["github.com/o/t"],
    "test_extension": ["github.com/o/x"],
}


def _record(rid: str, split: str, repo: str, lic: str, patched: bool, n: int) -> dict:
    return {
        "id": rid,
        "split": split,
        "repo": repo,
        "repos": [repo],
        "advisory_ids": [f"CVE-2020-{n}"],
        "cwes": ["CWE-078"],
        "language": "python",
        "path": f"pkg/mod{n}.py",
        "function": f"run{n}",
        "license_class": lic,
        "vulnerable": VULN.format(n=n),
        "patched": PATCHED.format(n=n) if patched else None,
    }


def build(root: Path, *, v2: bool = True) -> Path:
    (root / "work").mkdir(parents=True)
    (root / "reports").mkdir()
    (root / "licenses").mkdir()
    rows = [_record(*r, n) for n, r in enumerate(RECORDS)]
    name = "split-v2.jsonl" if v2 else "split.jsonl"
    (root / "work" / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
    negs = []
    for split, count in NEGATIVES.items():
        for i in range(count):
            repo = NEG_REPOS[split][i % len(NEG_REPOS[split])]
            negs.append(
                {
                    "id": f"neg-{split}-{i:02d}",
                    "split": split,
                    "repo": repo,
                    "repos": [repo],
                    "language": "python",
                    "path": f"pkg/other{i}.py",
                    "function": f"helper{i}",
                    "code": NEG.format(n=i),
                    "label": "negative_unchanged",
                }
            )
    (root / "work" / "negatives.jsonl").write_text("".join(json.dumps(n) + "\n" for n in negs))
    filters = {
        "excluded_ids": {"train": ["tr2"], "dev": ["dv3"], "test": [], "test_extension": []},
        "audit_confirmed_ids": {"train": ["tr1"], "dev": ["dv1"], "test": [], "test_extension": []},
    }
    (root / "reports" / "split-manifest-v2.json").write_text(json.dumps({"filters": filters}))
    (root / "licenses" / "licenses.csv").write_text(
        "repo,spdx_id\no/a,MIT\no/b,GPL-3.0\no/c,MIT\no/d,MIT\no/e,Apache-2.0\no/t,MIT\no/x,MIT\n"
    )
    return root


@pytest.fixture
def vul_root(tmp_path: Path) -> Path:
    return build(tmp_path / "vul")
