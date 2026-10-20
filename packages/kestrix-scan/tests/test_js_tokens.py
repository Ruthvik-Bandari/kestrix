# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The JavaScript/TypeScript tokenizer: strings, templates, comments, regex versus division, JSX, TS and bounds."""

import pytest

from kestrix_scan import js_tokens
from kestrix_scan.js_rules import check_js
from kestrix_scan.js_tokens import Token, tokenize


def kinds(source: str, **options: bool) -> list[tuple[str, str]]:
    tokens = tokenize(source, **options)
    assert tokens is not None
    return [(t.kind, t.value) for t in tokens]


def test_strings_with_escapes_and_both_quotes() -> None:
    assert kinds('a = \'it\\\'s\'; b = "say \\"hi\\""') == [
        ("name", "a"),
        ("punct", "="),
        ("str", "it's"),
        ("punct", ";"),
        ("name", "b"),
        ("punct", "="),
        ("str", 'say "hi"'),
    ]


def test_nested_template_literals() -> None:
    assert kinds("`a${`b${c}d`}e`") == [
        ("tpl_head", "a"),
        ("tpl_head", "b"),
        ("name", "c"),
        ("tpl_tail", "d"),
        ("tpl_tail", "e"),
    ]


def test_template_with_object_literal_and_middle_parts() -> None:
    assert kinds("`x${ {a: 1}.a }y${z}w`") == [
        ("tpl_head", "x"),
        ("punct", "{"),
        ("name", "a"),
        ("punct", ":"),
        ("num", "1"),
        ("punct", "}"),
        ("punct", "."),
        ("name", "a"),
        ("tpl_mid", "y"),
        ("name", "z"),
        ("tpl_tail", "w"),
    ]


def test_template_without_substitution_and_a_dollar_sign() -> None:
    assert kinds("`cost: $5 and \\${not}`") == [("tpl", "cost: $5 and ${not}")]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("x = a / b / c", ["name", "punct", "name", "punct", "name", "punct", "name"]),
        ("x = /ab+c/gi.test(s)", ["name", "punct", "regex", "punct", "name", "punct", "name", "punct"]),
        ("return /x/.test(y)", ["name", "regex", "punct", "name", "punct", "name", "punct"]),
        ("f(a) / 2", ["name", "punct", "name", "punct", "punct", "num"]),
        ("arr[0] / 2", ["name", "punct", "num", "punct", "punct", "num"]),
        ("x = [/a/, /b/]", ["name", "punct", "punct", "regex", "punct", "regex", "punct"]),
        ("i++ / 2", ["name", "punct", "punct", "num"]),
        ("obj.return / 2", ["name", "punct", "name", "punct", "num"]),
        ("x = /[/]/.source", ["name", "punct", "regex", "punct", "name"]),
        ("x /= 2", ["name", "punct", "num"]),
    ],
)
def test_regex_versus_division(source: str, expected: list[str]) -> None:
    assert [kind for kind, _ in kinds(source)] == expected


def test_a_regex_that_does_not_close_on_its_line_is_division() -> None:
    assert kinds("x = (a)\n/ b") == [
        ("name", "x"),
        ("punct", "="),
        ("punct", "("),
        ("name", "a"),
        ("punct", ")"),
        ("punct", "/"),
        ("name", "b"),
    ]


def test_comments_are_dropped_even_when_they_hold_quotes() -> None:
    source = "// it's a \"comment\" with `ticks`\n/* don't 'stop' */ a = 1 // trailing '\nb = 2"
    assert kinds(source) == [
        ("name", "a"),
        ("punct", "="),
        ("num", "1"),
        ("name", "b"),
        ("punct", "="),
        ("num", "2"),
    ]


def test_hashbang_and_html_comment_lines_are_skipped() -> None:
    assert kinds("#!/usr/bin/env node\n<!-- old\nx") == [("name", "x")]


def test_jsx_text_with_apostrophes_is_not_a_string() -> None:
    source = "const a = <p className=\"x\">Don't stop {name}. It's / fine</p>;\nconst b = 'ok';"
    assert kinds(source) == [
        ("name", "const"),
        ("name", "a"),
        ("punct", "="),
        ("jsx", "p"),
        ("jsx_attr", "className"),
        ("punct", "="),
        ("str", "x"),
        ("punct", "{"),
        ("name", "name"),
        ("punct", "}"),
        ("jsx", "/>"),
        ("punct", ";"),
        ("name", "const"),
        ("name", "b"),
        ("punct", "="),
        ("str", "ok"),
        ("punct", ";"),
    ]


def test_jsx_nested_elements_fragments_and_expression_attributes() -> None:
    source = "return (<><A on={() => go(`${x}`)} {...rest}><b>t</b><C/></A></>);"
    values = [value for _, value in kinds(source)]
    assert values == [
        "return",
        "(",
        "<>",
        "A",
        "on",
        "=",
        "{",
        "(",
        ")",
        "=>",
        "go",
        "(",
        "",
        "x",
        "",
        ")",
        "}",
        "{",
        "...",
        "rest",
        "}",
        "b",
        "C",
        "/>",
        ")",
        ";",
    ]


def test_less_than_after_an_operand_is_a_comparison_not_jsx() -> None:
    values = [v for _, v in kinds("if (a < b && c <d) {}")]
    assert values == ["if", "(", "a", "<", "b", "&&", "c", "<", "d", ")", "{", "}"]


def test_typescript_generics_and_annotations_are_plain_tokens() -> None:
    source = "const m: Map<string, Array<number>> = new Map<string, number[]>(); f<T>(x as T)"
    values = [v for _, v in kinds(source, jsx=False)]
    assert values[:12] == ["const", "m", ":", "Map", "<", "string", ",", "Array", "<", "number", ">>", "="]
    assert "as" in values


def test_tsx_generic_arrow_is_not_an_element() -> None:
    values = [v for _, v in kinds("const id = <T,>(x: T): T => x; const e = <T extends U>(y: T) => y;", tsx=True)]
    assert values[:6] == ["const", "id", "=", "<", "T", ","]
    assert "extends" in values


def test_tsx_text_starting_with_a_parenthesis_is_jsx() -> None:
    source = "const a = <span>(optional) it's fine</span>;\nconst b = 'ok';"
    assert kinds(source, tsx=True)[-4:] == [("name", "b"), ("punct", "="), ("str", "ok"), ("punct", ";")]


def test_type_assertion_in_ts_is_not_jsx() -> None:
    assert [k for k, _ in kinds("const x = <string>value;", jsx=False)] == [
        "name",
        "name",
        "punct",
        "punct",
        "name",
        "punct",
        "name",
        "punct",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "const s = 'unterminated\nconst t = 1",
        "const t = `never closed ${x",
        "/* open comment",
        "const re = /unclosed",
        "return <div>text {",
        "a = {{{{",
        "}}}) ]",
        "`${`${`",
        'x = "\\',
    ],
)
def test_unterminated_input_never_raises(source: str) -> None:
    tokens = tokenize(source)
    assert tokens is not None
    assert all(isinstance(token, Token) for token in tokens)
    assert isinstance(check_js(source, "broken.jsx"), list)


def test_unterminated_string_ends_at_the_line_break() -> None:
    assert kinds("s = 'abc\nnext = 1") == [
        ("name", "s"),
        ("punct", "="),
        ("str", "abc"),
        ("name", "next"),
        ("punct", "="),
        ("num", "1"),
    ]


def test_positions_are_one_based_lines_and_columns() -> None:
    tokens = tokenize("a\n  `x\ny`  b")
    assert tokens is not None
    assert [(t.value, t.line, t.col, t.end_line) for t in tokens] == [("a", 1, 1, 1), ("x\ny", 2, 3, 3), ("b", 3, 5, 3)]


def test_numbers() -> None:
    assert [v for _, v in kinds("0x1F 1_000 1.5e-3 .5 10n 0b101")] == ["0x1F", "1_000", "1.5e-3", ".5", "10n", "0b101"]


def test_too_many_tokens_or_too_deep_gives_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(js_tokens, "MAX_TOKENS", 10)
    assert tokenize("a b c d e f g h i j k l m") is None
    monkeypatch.setattr(js_tokens, "MAX_TOKENS", 500_000)
    assert tokenize("{\n" * (js_tokens.MAX_NESTING + 5)) is None
    assert check_js("{\n" * (js_tokens.MAX_NESTING + 5), "deep.js") == "too_complex"


@pytest.mark.parametrize(
    ("text", "rel"),
    [
        ("var a=1;" * 200, "bundle.js"),  # one 1,600-character line
        ("eval(x)\n", "vendor/app.min.js"),
        ("eval(x)\n", "lib/jquery-min.js"),
        ("x;\n" + "y" * 5000 + "\n", "long.ts"),
    ],
)
def test_minified_files_are_skipped(text: str, rel: str) -> None:
    assert check_js(text, rel) == "minified"


def test_long_but_ordinary_files_are_not_minified() -> None:
    assert check_js("const a = 1;\n" * 5000 + "eval(x)\n", "big.js") != "minified"
