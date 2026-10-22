# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Round-2 Python rule changes (judged on the tuning data, see docs/benchmarks/cvefixes.md): a positive and a negative
case for every kept change."""

import textwrap

import pytest

from kestrix_scan.python_rules import check_python
from kestrix_scan.registry import Hit


def hits(source: str) -> list[Hit]:
    result = check_python(textwrap.dedent(source), "app.py")
    assert isinstance(result, list), result
    return result


def ids(source: str) -> set[str]:
    return {hit.rule_id for hit in hits(source)}


def only(source: str, rule_id: str) -> Hit:
    (hit,) = [hit for hit in hits(source) if hit.rule_id == rule_id]
    return hit


# ----- r2.1 Flask route parameters and more Flask request sources


def test_flask_path_parameter_reaches_open() -> None:
    hit = only(
        "import os\nfrom flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/files/<path:filename>')\n"
        "def get(filename):\n"
        "    return open(os.path.join('/srv', filename)).read()\n",
        "py.path.traversal",
    )
    assert hit.confidence == "high" and "Flask URL parameter `filename`" in hit.message
    assert next(step.note for step in hit.trace) == "Flask URL parameter `filename` (source)"


@pytest.mark.parametrize(
    "route",
    ["@app.route('/f/<name>')", "@bp.get('/f/<string:name>')", "@app.route('/f/<name>', methods=['POST'])"],
)
def test_flask_string_route_parameters_are_sources(route: str) -> None:
    source = f"import os\nfrom flask import Flask\napp = Flask(__name__)\n{route}\ndef get(name):\n    return open(name).read()\n"
    assert "py.path.traversal" in ids(source)


@pytest.mark.parametrize(
    "case",
    [
        "@app.route('/n/<int:name>')\ndef get(name):\n    return open(name).read()\n",  # validated by the converter
        "@app.route('/n/<uuid:name>')\ndef get(name):\n    return open(name).read()\n",
        "@app.route('/n/<name>')\ndef get(other):\n    return open(other).read()\n",  # not the route's parameter
        "@app.route('/n/<path:name>')\ndef get(name):\n    return open(os.path.basename(name)).read()\n",
        "@app.route('/n')\ndef get(name='x'):\n    return open(name).read()\n",
    ],
)
def test_flask_route_parameter_negatives(case: str) -> None:
    assert "py.path.traversal" not in ids("import os\nfrom flask import Flask\napp = Flask(__name__)\n" + case)


def test_route_parameters_are_sources_only_in_flask_files() -> None:
    source = (
        "def route(p):\n    return lambda f: f\n@route('/f/<name>')\ndef get(name):\n    return open(name).read()\n"
    )
    assert "py.path.traversal" not in ids(source)


@pytest.mark.parametrize(
    "expr", ["request.view_args['f']", "request.get_data()", "request.query_string", "request.stream.read()"]
)
def test_more_flask_request_sources(expr: str) -> None:
    assert "py.path.traversal" in ids(f"from flask import request\ndef f():\n    open({expr})\n")


# ----- r2.2 request objects of other frameworks


@pytest.mark.parametrize(
    "setup",
    [
        "async def f(request):\n    name = request.match_info['name']\n    open(name)\n",
        "async def f(request):\n    name = (await request.json())['name']\n    open(name)\n",
        "def view(request):\n    open(request.data['name'])\n",
        "def view(request):\n    open(request.query_params.get('name'))\n",
        "async def f(request):\n    open(request.path_params['name'])\n",
        "def view(request):\n    open(request.matchdict['name'])\n",
        "def view(self):\n    open(self.request.query_arguments['n'])\n",
    ],
)
def test_request_objects_of_other_frameworks_are_sources(setup: str) -> None:
    prefix = "import tornado.web\n" if "self.request" in setup else ""
    assert "py.path.traversal" in ids(prefix + setup)


def test_tornado_and_bottle_and_falcon_sources_need_their_import() -> None:
    tornado = "def get(self):\n    open(self.get_argument('f'))\n"
    assert "py.path.traversal" in ids("import tornado.web\n" + tornado)
    assert "py.path.traversal" not in ids(tornado)
    assert "py.path.traversal" in ids("from bottle import request\ndef f():\n    open(request.query.f)\n")
    falcon = "def on_get(self, req, resp):\n    open(req.get_param('f'))\n"
    assert "py.path.traversal" in ids("import falcon\n" + falcon)
    assert "py.path.traversal" not in ids(falcon)


def test_request_name_that_is_an_import_is_not_a_source() -> None:
    assert "py.path.traversal" not in ids("from urllib import request\ndef f():\n    open(request.query)\n")


# ----- r2.4 HTTP session and client methods as SSRF sinks


@pytest.mark.parametrize(
    "call",
    [
        "session.get(u)",
        "self.session.post(u, data=b'')",
        "requests.Session().get(u)",
        "client.request('GET', u)",
        "api_client.get(url=u)",
    ],
)
def test_session_methods_fetch_urls(call: str) -> None:
    source = f"import requests\nfrom flask import request\ndef f(session, client, api_client):\n    u = request.args['u']\n    {call}\n"
    assert "py.ssrf.request" in ids(source)


@pytest.mark.parametrize(
    "call",
    [
        "session.get('https://api.example.com/x')",  # a literal URL
        "session.get('https://api.example.com/' + u)",  # a fixed scheme and host
        "cache.get(u)",  # not an HTTP client
        "session.get(str(7))",
    ],
)
def test_session_methods_need_a_tainted_url(call: str) -> None:
    source = (
        f"import requests\nfrom flask import request\ndef f(session, cache):\n    u = request.args['u']\n    {call}\n"
    )
    assert "py.ssrf.request" not in ids(source)


def test_session_methods_need_an_http_library_import() -> None:
    source = "from flask import request\ndef f(session):\n    session.get(request.args['u'])\n"
    assert "py.ssrf.request" not in ids(source)


# ----- r2.5 Markdown output marked as safe HTML


@pytest.mark.parametrize(
    "value",
    [
        "markdown.markdown(text)",
        "markdown.markdown(text, extensions=['extra'])",
        "mistune.markdown(text)",
    ],
)
def test_markdown_output_marked_safe(value: str) -> None:
    source = f"import markdown, mistune\nfrom django.utils.safestring import mark_safe\ndef f(text):\n    return mark_safe({value})\n"
    hit = only(source, "py.xss.markup")
    assert "Markdown" in hit.message and hit.confidence == "medium"


def test_markdown_output_through_a_name_and_markup() -> None:
    source = "import markdown\nfrom markupsafe import Markup\ndef f(text):\n    html = markdown.markdown(text)\n    return Markup(html)\n"
    assert "py.xss.markup" in ids(source)


@pytest.mark.parametrize(
    "value",
    [
        "bleach.clean(markdown.markdown(text))",  # a sanitizer wraps the renderer
        "nh3.clean(markdown.markdown(text))",
        "'<p>fixed</p>'",
        "render(text)",  # not a known Markdown renderer
    ],
)
def test_markdown_output_negatives(value: str) -> None:
    source = f"import bleach, markdown, nh3\nfrom django.utils.safestring import mark_safe\ndef f(text):\n    return mark_safe({value})\n"
    assert "py.xss.markup" not in ids(source)


def test_markdown_name_with_a_sanitized_assignment_is_quiet() -> None:
    source = (
        "import bleach, markdown\nfrom markupsafe import Markup\ndef f(text):\n"
        "    html = bleach.clean(markdown.markdown(text))\n    return Markup(html)\n"
    )
    assert "py.xss.markup" not in ids(source)


# ----- r2.6 shutil.unpack_archive without a filter


def test_unpack_archive_without_filter() -> None:
    hit = only("import shutil\ndef f(path, target):\n    shutil.unpack_archive(path, target)\n", "py.archive.extract")
    assert "unpack_archive" in hit.message


@pytest.mark.parametrize(
    "call",
    [
        "shutil.unpack_archive(path, target, filter='data')",
        "shutil.unpack_archive(path, target, None, 'data')",
        "shutil.unpack_archive('fixed.tar.gz', target)",  # a literal archive name
    ],
)
def test_unpack_archive_negatives(call: str) -> None:
    assert "py.archive.extract" not in ids(f"import shutil\ndef f(path, target):\n    {call}\n")
