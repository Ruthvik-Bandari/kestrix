# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
from kestrixvul.dedup import deduplicate, js_tokens, minhash, normalized, shingles, similarity, tokens

PY = "def f(a):\n    # check\n    if a:\n        return a + 1\n    return 0\n"
PY_REFORMATTED = "def f(a):  # entry\n\n    if a:   return a + 1\n    return 0"


def test_python_normalization_ignores_comments_and_whitespace():
    assert normalized(PY, "python") == normalized(PY_REFORMATTED, "python")
    assert normalized("    def m(self):\n        return 1\n", "python") == "def m ( self ) : return 1"


def test_js_lexer_drops_comments_but_keeps_strings():
    code = "function f(x) { // note\n  /* block */ return '//not a comment' + `a ${x}`; }"
    toks = js_tokens(code)
    assert "'//not a comment'" in toks and "`a ${x}`" in toks
    assert "note" not in " ".join(toks) and "block" not in " ".join(toks)


def _body(n: int, tweak: str = "") -> str:
    lines = [f"function handler{n}(req, res) {{"]
    lines += [f"  const v{i} = req.query.p{i} + {i};" for i in range(40)]
    lines.append(f"  res.send(v0{tweak});")
    lines.append("}")
    return "\n".join(lines)


def _other(tweak: str) -> str:
    lines = ["function render(items) {"]
    lines += [f"  out.push(items[{i}].name.toUpperCase() + '{i}');" for i in range(30)]
    lines.append(f"  return out.join('{tweak}');")
    lines.append("}")
    return "\n".join(lines)


def test_minhash_estimates_jaccard_for_near_and_distinct_code():
    a = minhash(shingles(tokens(_body(1), "javascript")))
    near = minhash(shingles(tokens(_body(1, " + 1"), "javascript")))
    other = minhash(shingles(tokens("function g(){ return [1,2,3].map(x => x * 2).filter(Boolean); }", "javascript")))
    assert len(a) == 128
    assert similarity(a, near) >= 0.9
    assert similarity(a, other) < 0.2


def _record(rid: str, source: str, vulnerable: str, patched: str | None, published: str = "2020-01-01") -> dict:
    return {
        "id": rid,
        "source": source,
        "language": "javascript",
        "published": published,
        "vulnerable": vulnerable,
        "patched": patched,
    }


def test_dedup_drops_unchanged_exact_and_near_duplicates_across_sources():
    records = [
        _record("m1", "morefixes", _body(1), _body(1, " + 2")),  # exact copy of c1's vulnerable function
        _record("c1", "cvefixes", _body(1), _body(1, " + 3")),
        _record("c2", "cvefixes", _body(5), _body(5) + "\n// only a comment"),  # unchanged once normalized
        _record("m2", "morefixes", _body(1, " + 9"), None),  # near duplicate of c1
        _record("m3", "morefixes", _other("x"), _other("y")),
        _record("m4", "morefixes", _body(9, "q") + "\n// unique", _other("y")),  # patched duplicates m3's
    ]
    kept, report = deduplicate(records)
    assert [r["id"] for r in kept] == ["c1", "m3"]
    stats = report["per_source_language"]
    assert stats["cvefixes/javascript"]["dropped_unchanged_after_normalization"] == 1
    assert stats["morefixes/javascript"]["dropped_exact_duplicate"] == 2
    assert stats["morefixes/javascript"]["dropped_near_duplicate"] == 1
    assert report["dropped_by_source_pair"]["morefixes->cvefixes"] == 2
    assert all(r["vulnerable_sha256"] for r in kept)
