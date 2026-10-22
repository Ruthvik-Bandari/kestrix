# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Slow-request limits: the in-app request-body deadline and the uvicorn connection limits."""

import asyncio
import json
import time

import pytest
from starlette.exceptions import HTTPException
from typer.testing import CliRunner

from kestrix.cli import app as cli
from kestrix.server.app import _StreamedBodyLimit

from .hosted_support import ACCESS, ORIGIN, REFRESH, cookie_value, csrf, sign_in
from .test_hosted_settings import BASE

SCOPE = {"type": "http", "path": "/api/forensics/url", "method": "POST"}


async def read_body(scope, receive, send):
    while True:
        message = await receive()
        if not message.get("more_body", False):
            return


def feeder(chunks, gap):
    """A ``receive`` that delivers ``chunks`` pieces of body, ``gap`` seconds apart (the last one ends the body)."""
    queue = list(chunks)

    async def receive():
        await asyncio.sleep(gap)
        if not queue:
            await asyncio.sleep(3600)  # the client went quiet
        chunk = queue.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(queue)}

    return receive


async def run(app, scope, receive):
    async def send(message):
        raise AssertionError("the app sends nothing in these tests")

    await app(scope, receive, send)


def limited(inner=read_body, **kwargs):
    return _StreamedBodyLimit(inner, **kwargs)


def test_a_body_that_stalls_is_cut_off_after_the_idle_time():
    queue = [{"type": "http.request", "body": b"a", "more_body": True}]

    async def one_piece_then_silence():
        if queue:
            return queue.pop(0)
        await asyncio.sleep(3600)
        return {"type": "http.request"}

    started = time.monotonic()
    with pytest.raises(HTTPException) as caught:
        asyncio.run(run(limited(idle_s=0.05), SCOPE, one_piece_then_silence))
    assert caught.value.status_code == 408
    assert time.monotonic() - started < 2


def test_a_slow_drip_is_cut_off_by_the_total_time_even_when_each_piece_is_on_time():
    started = time.monotonic()
    with pytest.raises(HTTPException) as caught:
        asyncio.run(run(limited(idle_s=0.1, total_s=0.2), SCOPE, feeder([b"x"] * 1000, 0.03)))
    assert caught.value.status_code == 408
    assert time.monotonic() - started < 2


def test_uploads_get_the_longer_total_time():
    app = limited(body_limits={"/api/forensics/file": 1000}, idle_s=0.1, total_s=0.05, upload_total_s=2.0)
    upload = {**SCOPE, "path": "/api/forensics/file"}
    asyncio.run(run(app, upload, feeder([b"x"] * 5, 0.03)))  # about 0.15 s in all: fine for an upload
    with pytest.raises(HTTPException) as caught:
        asyncio.run(run(app, SCOPE, feeder([b"x"] * 5, 0.03)))  # the same body to a small route is too slow
    assert caught.value.status_code == 408


def test_a_prompt_body_passes_and_the_size_cap_still_applies():
    asyncio.run(run(limited(idle_s=0.5), SCOPE, feeder([b"x" * 10], 0)))
    with pytest.raises(HTTPException) as caught:
        asyncio.run(run(limited(idle_s=0.5), SCOPE, feeder([b"x" * (1024 * 1024 + 1)], 0)))
    assert caught.value.status_code == 413


def test_reads_after_the_body_is_complete_are_never_timed():
    async def inner(scope, receive, send):
        await read_body(scope, receive, send)
        await receive()  # like a streaming response waiting for the client to disconnect

    with pytest.raises(asyncio.TimeoutError):  # the test's own timeout, not an HTTPException 408
        asyncio.run(asyncio.wait_for(run(limited(inner, idle_s=0.05), SCOPE, feeder([b"x"], 0)), 0.3))


def test_without_a_deadline_nothing_is_timed():
    asyncio.run(run(limited(), SCOPE, feeder([b"x", b"y"], 0.15)))


def test_the_hosted_app_answers_a_stalled_body_with_408_and_request_timeout(make_hosted, providers):
    client = make_hosted(body_idle_s=0.05)
    resp = sign_in(client, providers)
    headers = {"x-csrf-token": csrf(client)["x-csrf-token"], "origin": ORIGIN, "host": "kestrix.example"}
    cookies = f"{ACCESS}={cookie_value(resp, ACCESS)}; {REFRESH}={cookie_value(resp, REFRESH)}"
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/api/forensics/url",
        "raw_path": b"/api/forensics/url",
        "query_string": b"",
        "root_path": "",
        "client": ("203.0.113.9", 4000),
        "server": ("kestrix.example", 443),
        "headers": [
            *((k.encode(), v.encode()) for k, v in headers.items()),
            (b"cookie", cookies.encode()),
            (b"content-type", b"application/json"),
            (b"content-length", b"40"),
        ],
    }
    sent = []
    sent_body = [{"type": "http.request", "body": b'{"url": "', "more_body": True}]

    async def receive():
        if sent_body:
            return sent_body.pop(0)
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    started = time.monotonic()
    asyncio.run(client.app(scope, receive, send))
    assert time.monotonic() - started < 3
    assert sent[0]["status"] == 408
    body = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))
    assert body["reason"] == "request_timeout"
    assert dict(sent[0]["headers"])[b"cache-control"] == b"no-store"


def test_serve_hosted_passes_the_connection_limits_to_uvicorn(monkeypatch, tmp_path):
    import uvicorn

    for name, value in {**BASE, "KESTRIX_DB": str(tmp_path / "db" / "hosted.sqlite3")}.items():
        monkeypatch.setenv(name, value)
    served = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: served.append(kwargs))
    assert CliRunner().invoke(cli, ["serve-hosted"]).exit_code == 0
    options = served[0]
    assert options["timeout_keep_alive"] == 5
    assert options["h11_max_incomplete_event_size"] == 16 * 1024
    assert options["limit_concurrency"] == 100
    assert options["timeout_graceful_shutdown"] == 25
    assert options["proxy_headers"] is False and options["access_log"] is False
