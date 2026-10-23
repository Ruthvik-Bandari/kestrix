# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for web files: HTML, Vue and Svelte templates, Angular templates and CSS. Source is never run.

``html_tokens.py`` finds the start tags, attributes and ``<script>``/``<style>`` bodies; each rule matches one precise
shape in them and says less when a value cannot be judged from the text.

- ``.vue`` and ``.svelte``: ``v-html`` / ``{@html}`` with a value that is not a literal, ``:href`` / ``href={...}``
  (and the other attributes that run ``javascript:``) bound to a value that is not a literal.
- ``.html`` / ``.htm``: inline event handlers, ``javascript:`` URLs, ``target="_blank"`` without ``noopener``, forms that post over
  ``http:``, ``http:`` scripts, styles, frames and images, and Angular's ``[innerHTML]`` binding.
- ``.css`` / ``.scss``: remote ``@import`` and ``url()`` over ``http:`` and the legacy ``expression()``.
- ``<script>`` bodies (Vue and Svelte blocks, inline HTML scripts) go through the ``js.*`` rules, and ``<style>``
  bodies through the CSS rules, padded so findings carry the line numbers of the whole file.

Minified files are skipped as ``minified``, files over the tag bound as ``too_complex``. A script block that is too
complex for the JavaScript tokenizer is left out and the rest of the file is still checked.
"""

from __future__ import annotations

import re

from .html_tokens import Attr, Block, Doc, Positions, Tag, brace_end, scan
from .js_rules import check_js_source
from .models import Confidence, Severity, SkipReason, clip_snippet
from .registry import Hit

WEB_SUFFIXES = frozenset({".vue", ".svelte", ".html", ".htm", ".css", ".scss"})
MAX_AVERAGE_LINE = 500
_JS_TYPES = frozenset(
    {"", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}
)
_LOOPBACK = re.compile(r"^http://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])(?:[:/?#]|$)", re.IGNORECASE)
_HTTP = re.compile(r"^\s*http://", re.IGNORECASE)
_EXTERNAL = re.compile(r"^\s*(?:https?:)?//", re.IGNORECASE)
_TEMPLATE_SYNTAX = re.compile(r"\{\{|\{%|<%|<\?|\$\{")
_ROUTE_SOURCE = re.compile(
    r"\$route\b|\broute\.(?:query|params|fullPath|hash)|\$page\.(?:url|params)|\bsearchParams\b|\blocation\.(?:search|hash|href)\b"
    r"|\bqueryParams\b|\buseRoute\b"
)
_LITERAL = re.compile(r"""^(?:'[^'\\]*'|"[^"\\]*"|`[^`$\\]*`|-?\d[\d.]*|true|false|null|undefined)$""")
_SAFE_CALL = re.compile(r"^(?:[\w$]+\.)*(?:sanitize\w*|purify\w*|escape\w*|\$sanitize)\s*\(.*\)$", re.DOTALL)
_TRANSLATION = re.compile(r"""^\$?t\(\s*(?:'[^'\\]*'|"[^"\\]*")\s*\)$""")
_SAFE_URL_START = re.compile(r"""^[\s'"`]*(?:/(?![/\\])|#|https?://|mailto:|tel:)""", re.IGNORECASE)
_NOOP_JS_URL = re.compile(r"^\s*javascript:\s*(?:void\s*\(\s*0?\s*\)|;|undefined|false|)\s*;?\s*$", re.IGNORECASE)
_URL_ATTRS: dict[str, frozenset[str]] = {  # attribute -> elements where it can run javascript:
    "href": frozenset({"a", "area"}),
    "src": frozenset({"iframe", "frame", "embed"}),
    "action": frozenset({"form"}),
    "formaction": frozenset({"button", "input"}),
    "data": frozenset({"object"}),
}
_JS_URL_ATTRS = frozenset({"href", "src", "action", "formaction", "data", "xlink:href"})
_HANDLER = re.compile(r"^on[a-z]{3,}$")
_LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload", "icon"})
_SVELTE_HTML = re.compile(r"\{@html\s")
_SVELTE_ATTR_EXPR = re.compile(r"\{([^{}]*)\}")
_CSS_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.DOTALL)
_SCSS_LINE_COMMENT = re.compile(r"(?m)(?:^|(?<=[\s;{}]))//[^\n]*")
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*)?['"]?\s*(http://[^\s'")]+)""", re.IGNORECASE)
_CSS_URL = re.compile(r"""url\(\s*['"]?\s*(http://[^\s'")]+)""", re.IGNORECASE)
_CSS_EXPRESSION = re.compile(r"(?<![\w-])expression\s*\(", re.IGNORECASE)

ANGULAR_INNER_HTML = (
    "[innerHTML] binds a value that is not a literal. Angular sanitizes it unless the value was marked trusted "
    "(bypassSecurityTrustHtml), so check where the value comes from."
)


def minified(text: str, rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if ".min." in name or name.endswith(("-min.js", "-min.css")):
        return True
    return len(text) / (text.count("\n") + 1) > MAX_AVERAGE_LINE


class _Out:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.hits: list[Hit] = []

    def add(
        self,
        rule_id: str,
        line: int,
        col: int,
        message: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        self.hits.append(
            Hit(rule_id, line, col, line, message, clip_snippet(text), severity=severity, confidence=confidence)
        )


def check_web(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one HTML, Vue, Svelte or CSS file, or the reason it was not analyzed."""
    if minified(text, rel):
        return "minified"
    suffix = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    out = _Out(text.splitlines())
    if suffix in (".css", ".scss"):
        _css(text, out, scss=suffix == ".scss")
        return _unique(out.hits)
    doc = scan(text)
    if doc is None:
        return "too_complex"
    if suffix in (".vue", ".svelte"):
        _framework_templates(doc, text, suffix, out)
    else:
        _html(doc, out)
    for block in doc.blocks:
        _block(block, text, rel, out)
    return _unique(out.hits)


def _unique(hits: list[Hit]) -> list[Hit]:
    unique: dict[tuple[str, int], Hit] = {}
    for item in hits:
        unique.setdefault((item.rule_id, item.line), item)
    return list(unique.values())


def _padded(text: str, block: Block) -> str:
    """The block body behind blank lines and spaces, so a finding's line and column are the file's."""
    return "\n" * (block.line - 1) + " " * (block.col - 1) + text[block.start : block.end]


def _block(block: Block, text: str, rel: str, out: _Out) -> None:
    tag = block.tag
    lang = ((tag.attr("lang") or Attr("", None, 0, 0)).value or "").lower()
    body = _padded(text, block)
    if tag.name == "style":
        if lang in ("", "css", "scss"):
            _css(body, out, scss=lang == "scss")
        return
    kind = ((tag.attr("type") or Attr("", None, 0, 0)).value or "").lower().strip()
    if kind not in _JS_TYPES or lang not in ("", "js", "javascript", "ts", "typescript", "jsx", "tsx"):
        return
    # a '.ts' pass reads <T>x as a type assertion; JSX only when the block says so
    hits = check_js_source(body, rel, jsx=lang in ("jsx", "tsx"), tsx=lang == "tsx")
    if isinstance(hits, list):
        out.hits.extend(hits)


# ----- Vue, Svelte, Angular and plain HTML


def _literal(expression: str) -> bool:
    return not expression.strip() or bool(_LITERAL.match(expression.strip()))


def _route_traced(expression: str) -> bool:
    return bool(_ROUTE_SOURCE.search(expression))


def _raw_html(rule_id: str, attr: Attr, expression: str, out: _Out, what: str) -> None:
    expression = expression.strip()
    if _literal(expression) or _SAFE_CALL.match(expression) or _TRANSLATION.match(expression):
        return
    if _route_traced(expression):
        out.add(rule_id, attr.line, attr.col, f"{what} renders {expression[:60]!r}, which comes from the route or URL.")
    else:
        out.add(
            rule_id,
            attr.line,
            attr.col,
            f"{what} renders a value that is not a literal.",
            severity="medium",
            confidence="medium",
        )


def _url_binding(tag: Tag, attr: Attr, expression: str, out: _Out, what: str, *, braces: bool) -> None:
    expression = expression.strip()
    if _literal(expression) or _SAFE_URL_START.match(expression):
        return
    if braces and not expression:
        return
    message = (
        f"{what} on <{tag.name}> takes a value that is not a literal; a javascript: URL in it runs script on click."
    )
    if _route_traced(expression):
        out.add("web.url.dynamic_scheme", attr.line, attr.col, message, severity="medium", confidence="medium")
    else:
        out.add("web.url.dynamic_scheme", attr.line, attr.col, message, severity="low", confidence="low")


def _framework_templates(doc: Doc, text: str, suffix: str, out: _Out) -> None:
    for tag in doc.tags:
        for attr in tag.attrs:
            name = attr.name
            value = attr.value
            if value is None:
                continue
            if suffix == ".vue":
                if name == "v-html":
                    _raw_html("vue.xss.v_html", attr, value, out, "v-html")
                    continue
                target = name[1:] if name.startswith(":") else name[7:] if name.startswith("v-bind:") else ""
                target = target.partition(".")[0].lower()
                if target in _URL_ATTRS and tag.name in _URL_ATTRS[target]:
                    _url_binding(tag, attr, value, out, f"{name}", braces=False)
            else:
                lname = name.lower()
                if lname in _URL_ATTRS and tag.name in _URL_ATTRS[lname] and "{" in value:
                    expressions = _SVELTE_ATTR_EXPR.findall(value)
                    if value.lstrip().startswith("{") or not _SAFE_URL_START.match(value):
                        joined = expressions[0] if expressions else value
                        _url_binding(tag, attr, joined, out, f"{name}={{...}}", braces=True)
    if suffix == ".svelte":
        pos = Positions(text)
        for lo, hi in doc.markup:
            start = lo
            while True:
                match = _SVELTE_HTML.search(text, start, hi)
                if match is None:
                    break
                open_ = text.rfind("{", match.start(), match.end())
                end = brace_end(text, open_, hi)
                start = match.end() if end < 0 else end
                if end < 0:
                    continue
                expression = text[match.end() : end - 1]
                line, col = pos.line_col(open_)
                attr = Attr("{@html}", expression, line, col)
                _raw_html("svelte.xss.at_html", attr, expression, out, "{@html}")


def _html(doc: Doc, out: _Out) -> None:
    for tag in doc.tags:
        for attr in tag.attrs:
            lname = attr.lname
            value = attr.value or ""
            if _HANDLER.match(lname) and value.strip():
                out.add(
                    "html.inline.event_handler",
                    attr.line,
                    attr.col,
                    f"The {lname} attribute runs inline script, which a Content-Security-Policy without 'unsafe-inline' blocks.",
                )
            elif (
                lname in _JS_URL_ATTRS
                and value.lstrip().lower().startswith("javascript:")
                and not _NOOP_JS_URL.match(value)
            ):
                out.add(
                    "html.url.javascript_scheme",
                    attr.line,
                    attr.col,
                    f"{lname}=\"javascript:...\" runs inline script, which a Content-Security-Policy without 'unsafe-inline' blocks.",
                )
            elif (
                lname.startswith("[")
                and lname.strip("[]").lower() in ("innerhtml", "outerhtml")
                and not _literal(value)
            ):
                out.add("html.angular.inner_html", attr.line, attr.col, ANGULAR_INNER_HTML)
        _target_blank(tag, out)
        _http_resources(tag, out)


def _target_blank(tag: Tag, out: _Out) -> None:
    if tag.name not in ("a", "area"):
        return
    target, href, rel = tag.attr("target"), tag.attr("href"), tag.attr("rel")
    if target is None or (target.value or "").strip().lower() != "_blank" or href is None:
        return
    link = href.value or ""
    if not _EXTERNAL.match(link):
        return
    relation = (rel.value or "").lower() if rel is not None else ""
    if "noopener" in relation or "noreferrer" in relation or _TEMPLATE_SYNTAX.search(relation):
        return
    out.add(
        "html.link.target_blank",
        target.line,
        target.col,
        'target="_blank" to an external page without rel="noopener": the opened page can reach window.opener on older browsers.',
    )


def _http_resources(tag: Tag, out: _Out) -> None:
    if tag.name == "form":
        action = tag.attr("action")
        if action is not None and _HTTP.match(action.value or "") and not _LOOPBACK.match((action.value or "").strip()):
            out.add(
                "html.form.http_action",
                action.line,
                action.col,
                "This form posts to an http: URL, so what the user types crosses the network unencrypted.",
            )
        return
    attr_name = {"script": "src", "iframe": "src", "img": "src", "link": "href"}.get(tag.name)
    if attr_name is None:
        return
    attr = tag.attr(attr_name)
    if attr is None or not _HTTP.match(attr.value or "") or _LOOPBACK.match((attr.value or "").strip()):
        return
    if tag.name == "link":
        rel = tag.attr("rel")
        if rel is None or not (set((rel.value or "").lower().split()) & _LINK_RELS):
            return
    out.add(
        "html.mixed.http_resource",
        attr.line,
        attr.col,
        f"<{tag.name} {attr_name}> loads an http: URL; on an https page the browser blocks or downgrades it, and on http it can be altered in transit.",
    )


# ----- CSS


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _css(text: str, out: _Out, *, scss: bool) -> None:
    clean = _CSS_COMMENT.sub(_blank, text)
    if scss:
        clean = _SCSS_LINE_COMMENT.sub(_blank, clean)
    where = Positions(clean).line_col

    for pattern, rule, what in (
        (_CSS_IMPORT, "css.import.http", "@import"),
        (_CSS_URL, "css.import.http", "url()"),
    ):
        for match in pattern.finditer(clean):
            if _LOOPBACK.match(match.group(1)):
                continue
            line, col = where(match.start())
            out.add(
                rule,
                line,
                col,
                f"{what} loads {match.group(1)[:80]} over http:, so the stylesheet or asset can be altered in transit.",
            )
    for match in _CSS_EXPRESSION.finditer(clean):
        head = clean[max(0, match.start() - 200) : match.start()]
        declaration = head[max(head.rfind(";"), head.rfind("{"), head.rfind("}")) + 1 :]
        if ":" in declaration:
            line, col = where(match.start())
            out.add(
                "css.expression.legacy",
                line,
                col,
                "expression() runs script inside a stylesheet (Internet Explorer 7 and older).",
            )
