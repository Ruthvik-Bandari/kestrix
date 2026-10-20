# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
from kestrixvul.negatives import PER_COMMIT, select


def _fn(name: str, n: int, tweak: str = "") -> str:
    body = [f"def {name}(req):"] + [f"    v{i} = req.args.get('p{i}') or {i}" for i in range(n)]
    return "\n".join([*body, f"    return v0{tweak}"])


VULN = _fn("handler", 30)
POOL = [{"id": "p1", "language": "python", "vulnerable": VULN, "patched": VULN.replace("return v0", "return esc(v0)")}]
ASSIGNED = [
    {"id": "p1", "repos": ["github.com/o/p"], "advisory_ids": ["CVE-2025-1"], "split": "test"},
    {"id": "p2", "repos": ["github.com/o/old"], "advisory_ids": [], "split": "train"},
]


def _cand(rid: str, code: str, repo: str = "github.com/o/p", published: str = "2025-01-01", commit: str = "c1") -> dict:
    return {
        "id": rid,
        "commit": commit,
        "repos": [repo],
        "advisory_ids": [],
        "published": published,
        "language": "python",
        "origin": "changed_file",
        "code": code,
    }


def test_negatives_similar_to_a_vulnerable_function_are_dropped():
    candidates = [
        _cand("near", _fn("handler", 30, " + 1")),  # a light edit of the vulnerable function
        _cand("other", "def render(items):\n    out = [str(i) for i in items]\n    return ', '.join(out)"),
        _cand("same", VULN.replace("return v0", "return esc(v0)")),  # the patched function itself
    ]
    kept, report = select(candidates, POOL, ASSIGNED)
    assert [n["id"] for n in kept] == ["other"]
    assert kept[0]["split"] == "test" and kept[0]["code_sha256"]
    assert report["counts"]["dropped:similar_to_vulnerable"] == 1
    assert report["counts"]["dropped:exact_duplicate"] == 1


def test_negatives_follow_the_split_group_and_date_rule():
    candidates = [
        _cand(
            "late", "def a(x):\n    y = x\n    return y", repo="github.com/o/old", published="2025-01-01", commit="c2"
        ),
        _cand("orphan", "def b(x):\n    y = x * 2\n    return y", repo="github.com/z/z", commit="c3"),
        _cand(
            "ok", "def c(x):\n    y = x - 3\n    return y", repo="github.com/o/old", published="2019-01-01", commit="c4"
        ),
    ]
    kept, report = select(candidates, POOL, ASSIGNED)
    assert [(n["id"], n["split"]) for n in kept] == [("ok", "train")]
    assert report["counts"]["dropped:post_cutoff_commit_in_pre_cutoff_split"] == 1
    assert report["counts"]["dropped:no_split_group"] == 1


def test_negatives_are_capped_per_commit_and_deduplicated():
    candidates = [
        _cand(f"f{i}", f"def f{i}(x):\n    y = x + {i} * {i}\n    z = y // {i + 1}\n    return z % {i + 7}")
        for i in range(PER_COMMIT + 10)
    ]
    candidates.append(_cand("dup", candidates[0]["code"]))
    kept, report = select(candidates, POOL, ASSIGNED)
    assert len(kept) == PER_COMMIT
    assert report["counts"]["dropped:per_commit_cap"] + report["counts"].get("dropped:exact_duplicate", 0) == 11
