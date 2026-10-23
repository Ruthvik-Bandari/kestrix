# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 1 web stack: HTML, Vue, Svelte, Angular and CSS rules, the tag scanner and suppression in each syntax.

A positive and a negative case for every rule."""

import textwrap
import time
from pathlib import Path

import pytest

from kestrix_scan.analyze import scan_text
from kestrix_scan.html_tokens import MAX_TAGS, scan
from kestrix_scan.js_rules import check_js
from kestrix_scan.registry import RULES, Hit
from kestrix_scan.walk import Candidate
from kestrix_scan.web_rules import check_web


def hits(source: str, rel: str) -> list[Hit]:
    result = check_web(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return result


def ids(source: str, rel: str) -> set[str]:
    return {h.rule_id for h in hits(source, rel)}


def js_ids(source: str, rel: str) -> set[str]:
    result = check_js(source, rel)
    assert isinstance(result, list), result
    return {h.rule_id for h in result}


def tpl(body: str) -> str:
    return f"<template>{body}</template>"


# (rule id, file name, source that fires, source that does not)
CASES = [
    (
        "vue.xss.v_html",
        "A.vue",
        tpl('<div v-html="post.body"></div>'),
        tpl('<div v-html="DOMPurify.sanitize(post.body)"></div>'),
    ),
    (
        "vue.xss.v_html",
        "A.vue",
        tpl("<div v-html=\"$t('a', {n: name})\"></div>"),
        tpl("<div v-html=\"$t('a')\"></div>"),
    ),
    ("vue.xss.v_html", "A.vue", tpl('<p v-html="html"></p>'), tpl("<p v-html=\"'<b>x</b>'\"></p>")),
    ("svelte.xss.at_html", "A.svelte", "<p>{@html post.body}</p>", "<p>{@html DOMPurify.sanitize(post.body)}</p>"),
    ("svelte.xss.at_html", "A.svelte", "<p>{@html cache[key]}</p>", '<p>{@html "<b>x</b>"}</p>'),
    ("web.url.dynamic_scheme", "A.vue", tpl('<a :href="link">x</a>'), tpl("<a :href=\"'/u/' + id\">x</a>")),
    ("web.url.dynamic_scheme", "A.vue", tpl('<a v-bind:href="next">x</a>'), tpl('<img :src="photo">')),
    ("web.url.dynamic_scheme", "A.svelte", "<a href={url}>x</a>", '<a href="/x/{id}">x</a>'),
    ("html.inline.event_handler", "a.html", '<button onclick="go()">x</button>', '<button id="go">x</button>'),
    ("html.url.javascript_scheme", "a.html", '<a href="javascript:run()">x</a>', '<a href="javascript:void(0)">x</a>'),
    (
        "html.link.target_blank",
        "a.html",
        '<a href="https://x.com" target="_blank">x</a>',
        '<a href="https://x.com" target="_blank" rel="noopener noreferrer">x</a>',
    ),
    (
        "html.link.target_blank",
        "a.html",
        '<a href="//x.com" target=_blank>x</a>',
        '<a href="/local" target="_blank">x</a>',
    ),
    (
        "html.form.http_action",
        "a.html",
        '<form action="http://x.com/login"></form>',
        '<form action="https://x.com/login"></form>',
    ),
    (
        "html.mixed.http_resource",
        "a.html",
        '<script src="http://cdn.x.com/a.js"></script>',
        '<script src="https://cdn.x.com/a.js"></script>',
    ),
    (
        "html.mixed.http_resource",
        "a.html",
        '<link rel="stylesheet" href="http://x.com/a.css">',
        '<link rel="canonical" href="http://x.com/">',
    ),
    (
        "html.mixed.http_resource",
        "a.html",
        '<iframe src="http://x.com/f"></iframe>',
        '<img src="http://localhost:3000/a.png">',
    ),
    ("html.angular.inner_html", "a.html", '<div [innerHTML]="body"></div>', "<div [innerHTML]=\"'<b>x</b>'\"></div>"),
    ("css.import.http", "a.css", "@import url(http://x.com/a.css);", "@import url(https://x.com/a.css);"),
    (
        "css.import.http",
        "a.scss",
        ".a { background: url('http://x.com/a.png'); }",
        "// url(http://x.com/a.png)\n.a { color: red; }",
    ),
    (
        "css.expression.legacy",
        "a.css",
        ".a { width: expression(document.body.clientWidth); }",
        "/* width: expression(1) */\n.a { width: 10px; }",
    ),
]


@pytest.mark.parametrize(("rule", "name", "bad", "good"), CASES)
def test_rule_fires_and_stays_quiet(rule: str, name: str, bad: str, good: str) -> None:
    assert rule in ids(bad, name)
    assert rule not in ids(good, name)


def test_every_web_rule_is_covered_here() -> None:
    covered = {case[0] for case in CASES}
    registry = {r.id for r in RULES.values() if r.language == "web" and r.id != "next.images.wildcard_host"}
    assert covered == registry


def test_route_traced_values_are_raised() -> None:
    traced = hits(tpl('<a :href="$route.query.next">x</a><div v-html="$route.query.q"></div>'), "A.vue")
    assert {(h.rule_id, h.severity) for h in traced} == {("web.url.dynamic_scheme", "medium"), ("vue.xss.v_html", None)}
    plain = hits(tpl('<a :href="link">x</a><div v-html="html"></div>'), "A.vue")
    assert {(h.rule_id, h.severity) for h in plain} == {("web.url.dynamic_scheme", "low"), ("vue.xss.v_html", "medium")}


def test_html_rules_do_not_run_on_vue_templates() -> None:
    source = tpl('<a href="https://x.com" target="_blank">x</a><button onclick="go()">x</button>')
    assert ids(source, "A.vue") == set()


def test_script_blocks_run_the_js_rules_with_file_line_numbers() -> None:
    source = (
        '<template>\n  <p>x</p>\n</template>\n\n<script setup lang="ts">\nimport { ref } from "vue"\n'
        "const a = ref(1)\neval(userText)\n</script>\n"
    )
    assert [(h.rule_id, h.line) for h in hits(source, "A.vue")] == [("js.exec.eval", 8)]
    svelte = hits("<p>hi</p>\n<script>\n  let x = 1;\n  eval(code);\n</script>", "A.svelte")
    assert [(h.rule_id, h.line) for h in svelte] == [("js.exec.eval", 4)]
    inline = hits("<html>\n<body>\n<script>document.write(location.hash)</script>\n</body></html>", "a.html")
    assert [(h.rule_id, h.line) for h in inline] == [("js.dom.xss_sink", 3)]


def test_script_types_that_are_not_javascript_are_not_scanned() -> None:
    source = '<script type="application/ld+json">{"a": "eval(x)"}</script><script type="text/template">eval(x)</script>'
    assert ids(source, "a.html") == set()


def test_style_blocks_run_the_css_rules_with_file_line_numbers() -> None:
    found = hits("<div></div>\n<style>\n.a {\n  background: url(http://x.com/a.png);\n}\n</style>", "a.html")
    assert [(h.rule_id, h.line) for h in found] == [("css.import.http", 4)]


def test_angular_inline_template_in_ts() -> None:
    bad = '@Component({ template: `<div [innerHTML]="body"></div>` })\nclass A {}'
    assert js_ids(bad, "a.component.ts") == {"html.angular.inner_html"}
    assert js_ids("@Component({ template: `<div>{{ body }}</div>` })\nclass A {}", "a.component.ts") == set()


@pytest.mark.parametrize(
    ("method", "arg", "fires"),
    [
        ("bypassSecurityTrustHtml", "value", True),
        ("bypassSecurityTrustUrl", "this.url", True),
        ("bypassSecurityTrustResourceUrl", "'https://x.com/' + id", True),
        ("bypassSecurityTrustScript", "code", True),
        ("bypassSecurityTrustStyle", "css", True),
        ("bypassSecurityTrustHtml", "'<b>fixed</b>'", False),
        ("bypassSecurityTrustHtml", "DOMPurify.sanitize(value)", False),
        ("bypassSecurityTrustOther", "value", False),
    ],
)
def test_angular_bypass_security_trust(method: str, arg: str, fires: bool) -> None:
    source = f"class A {{ f(s: DomSanitizer, value: string) {{ return s.{method}({arg}); }} }}"
    assert ("js.angular.bypass_trust" in js_ids(source, "a.ts")) is fires


def test_angular_bypass_of_a_url_value_is_high_and_traced() -> None:
    found = check_js("function f(s) { return s.bypassSecurityTrustHtml(location.hash); }", "a.ts")
    assert isinstance(found, list) and found[0].severity is None and found[0].trace


@pytest.mark.parametrize(
    ("name", "source", "fires"),
    [
        (
            "next.config.js",
            "module.exports = { images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] } };",
            True,
        ),
        ("next.config.mjs", "export default { images: { remotePatterns: [{ hostname: '**' }] } };", True),
        ("next.config.ts", "const c: NextConfig = { images: { remotePatterns: [{ hostname: '**' }] } };", True),
        (
            "next.config.js",
            "module.exports = { images: { remotePatterns: [{ hostname: 'img.example.com' }] } };",
            False,
        ),
        ("next.config.js", "module.exports = { images: { remotePatterns: [{ hostname: '*.example.com' }] } };", False),
        ("config.js", "module.exports = { images: { remotePatterns: [{ hostname: '**' }] } };", False),
        ("next.config.js", "module.exports = { async headers() { return []; } };", False),
    ],
)
def test_next_images_wildcard_host(name: str, source: str, fires: bool) -> None:
    assert ("next.images.wildcard_host" in js_ids(source, name)) is fires


# ----- suppression in each syntax


def _scan(tmp_path: Path, name: str, text: str) -> tuple[set[str], list[str]]:
    findings, notes, _, skip = scan_text(text, Candidate(path=tmp_path / name, rel=name))
    return {f.rule_id for f in findings}, [n.id for n in notes] + ([skip.reason] if skip else [])


SUPPRESSED = [
    (
        "A.vue",
        "vue.xss.v_html",
        "<!-- kestrix: ignore[vue.xss.v_html] sanitized upstream -->\n",
        '<div v-html="html"></div>',
    ),
    (
        "a.html",
        "html.inline.event_handler",
        "<!-- kestrix: ignore[html.inline.event_handler] legacy page -->\n",
        '<button onclick="go()">x</button>',
    ),
    (
        "A.svelte",
        "svelte.xss.at_html",
        "<!-- kestrix: ignore[svelte.xss.at_html] our own build output -->\n",
        "{@html html}",
    ),
    (
        "a.css",
        "css.import.http",
        "/* kestrix: ignore[css.import.http] vendor mirror, reviewed */\n",
        "@import url(http://x.com/a.css);",
    ),
    (
        "a.scss",
        "css.import.http",
        "// kestrix: ignore[css.import.http] vendor mirror, reviewed\n",
        "@import url(http://x.com/a.css);",
    ),
]


@pytest.mark.parametrize(("name", "rule", "comment", "line"), SUPPRESSED)
def test_suppression_with_a_reason_in_each_syntax(
    tmp_path: Path, name: str, rule: str, comment: str, line: str
) -> None:
    assert _scan(tmp_path, name, comment + line) == (set(), [])
    assert rule in _scan(tmp_path, name, line)[0]


def test_suppression_without_a_reason_suppresses_nothing(tmp_path: Path) -> None:
    text = '<!-- kestrix: ignore[html.inline.event_handler] -->\n<button onclick="go()">x</button>'
    assert _scan(tmp_path, "a.html", text) == ({"html.inline.event_handler"}, ["kestrix.suppression.missing_reason"])


def test_script_block_findings_take_js_comment_suppression(tmp_path: Path) -> None:
    text = "<script>\n  // kestrix: ignore[js.exec.eval] constant expression, reviewed\n  eval('1+1' + x);\n</script>"
    assert _scan(tmp_path, "a.vue", text) == (set(), [])


# ----- the tag scanner


def test_tag_scanner_reads_attributes_and_blocks() -> None:
    doc = scan("<a href=\"x>y\" :class='{a: b > c}' data-n=5 hidden>t</a><script>if (a < b) {}</script>")
    assert doc is not None
    attrs = [(a.name, a.value) for a in doc.tags[0].attrs]
    assert attrs == [("href", "x>y"), (":class", "{a: b > c}"), ("data-n", "5"), ("hidden", None)]
    assert len(doc.blocks) == 1 and doc.blocks[0].tag.name == "script"


def test_tag_scanner_skips_comments_and_non_html_templates() -> None:
    doc = scan('<!-- <a href="x"> --><template lang="pug">a(href="y")</template><p id=q>')
    assert doc is not None
    assert [t.name for t in doc.tags] == ["template", "p"]


def test_svelte_braces_in_attributes() -> None:
    doc = scan("<a href={a > b ? '}' : c} {...rest} {title}>x</a>")
    assert doc is not None
    assert [a.name for a in doc.tags[0].attrs] == ["href", "{...rest}", "{title}"]
    assert doc.tags[0].attrs[0].value == "{a > b ? '}' : c}"


@pytest.mark.parametrize(
    "source",
    ["<a href='x", "<a", "<!-- x", "<script>eval(", "<a b=", "<<<<>>>>", "<a {{{{", "<style>@import", "</", "<"],
)
def test_malformed_input_never_raises(source: str) -> None:
    assert scan(source) is not None
    for name in ("a.html", "a.vue", "a.svelte", "a.css"):
        assert isinstance(check_web(source, name), list)


def test_tag_bound_gives_too_complex() -> None:
    assert scan("<a>" * (MAX_TAGS + 1)) is None
    assert check_web("<a>\n" * (MAX_TAGS + 1), "a.html") == "too_complex"


def test_pathological_input_is_fast() -> None:
    started = time.perf_counter()
    for source in (
        '<a b="' * 20000,
        "<a " + "{" * 50000,
        "<!--" * 20000,
        "<a b=c " * 30000,
        "@import 'http://" * 20000,
    ):
        for name in ("a.html", "a.svelte", "a.css"):
            check_web(source, name)
    assert time.perf_counter() - started < 20


def test_minified_files_are_skipped() -> None:
    assert check_web("a{b:c}" * 500, "a.css") == "minified"
    assert check_web("<a>", "lib.min.css") == "minified"


def test_scan_routes_web_files_and_skips_minified_and_build_output(tmp_path: Path) -> None:
    from kestrix_scan import scan

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.vue").write_text('<template>\n  <div v-html="body"></div>\n</template>\n')
    (tmp_path / "src" / "page.html").write_text('<form action="http://example.com/x"></form>\n')
    (tmp_path / "src" / "site.min.css").write_text("@import url(http://example.com/a.css);")
    (tmp_path / "src" / "big.css").write_text("a{b:c}" * 500)
    (tmp_path / ".next").mkdir()
    (tmp_path / ".next" / "out.html").write_text('<form action="http://example.com/x"></form>\n')
    report = scan([tmp_path], root=tmp_path)
    assert [(f.path, f.rule_id, f.line) for f in report.findings] == [
        ("src/App.vue", "vue.xss.v_html", 2),
        ("src/page.html", "html.form.http_action", 1),
    ]
    assert {(s.path, s.reason) for s in report.files_skipped} == {
        ("src/big.css", "minified"),
        ("src/site.min.css", "minified"),
    }
