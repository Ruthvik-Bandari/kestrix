# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted analyses run in limited worker processes (server/isolation.py).

The functions below run inside the worker, so they live at module level (the worker imports
them by name). Limits are shrunk so the tests stay fast.
"""

import os
import sys
import time

import anyio
import pytest
from pydantic import BaseModel

from kestrix.core.errors import Reason, Rejected
from kestrix.forensics import api as forensics_api
from kestrix.mail.analyze import analyze
from kestrix.mail.models import MailReport
from kestrix.server.isolation import ENV_ALLOWLIST, Isolator, Limits

from .hosted_support import csrf, sign_in


class Names(BaseModel):
    names: list[str]


def env_names() -> Names:
    return Names(names=sorted(os.environ))


def sleep_forever(_: str) -> Names:
    time.sleep(60)
    return Names(names=[])


def spin() -> Names:
    while True:
        pass


def crash_with_input(text: str) -> Names:
    raise ValueError(text)


def die() -> Names:
    os._exit(3)


def hog_memory() -> Names:
    blocks = [bytearray(64 * 1024 * 1024) for _ in range(64)]  # 4 GiB, far over the limit
    return Names(names=[str(len(blocks))])


def run(isolator: Isolator, fn, model, *args, **kwargs):
    async def main():
        return await isolator.run(fn, model, *args, **kwargs)

    return anyio.run(main)


@pytest.fixture(scope="module")
def isolator():
    isolator = Isolator(Limits(cpu_s=2, wall_s=5))
    isolator.start()
    return isolator


def test_isolated_report_equals_the_in_process_one(isolator):
    raw = b"From: a@mail.example\r\nReply-To: pay@other.example\r\nSubject: hi\r\n\r\nhello https://x.example/\r\n"
    assert run(isolator, analyze, MailReport, raw) == analyze(raw)


def test_rejections_come_back_as_rejections(isolator):
    with pytest.raises(Rejected) as exc:
        run(isolator, analyze, MailReport, b"\x00\x01garbage")
    assert exc.value.reason is Reason.INVALID_INPUT


def test_workers_never_see_secrets(monkeypatch):
    monkeypatch.setenv("KESTRIX_SESSION_PEPPER", "pepper-" + "s" * 40)
    monkeypatch.setenv("KESTRIX_GITHUB_CLIENT_SECRET", "github-secret-value")
    isolator = Isolator()
    isolator.start()
    names = run(isolator, env_names, Names).names
    # macOS adds __CF_USER_TEXT_ENCODING to every process; nothing else beyond the allowlist.
    assert set(names) - {"__CF_USER_TEXT_ENCODING"} <= set(ENV_ALLOWLIST)
    assert os.environ["KESTRIX_SESSION_PEPPER"].startswith("pepper-")  # the server's own environment is restored


def test_wall_clock_deadline_kills_the_worker():
    started = time.monotonic()
    with pytest.raises(Rejected) as exc:
        run(Isolator(Limits(wall_s=0.5)), sleep_forever, Names, "x")
    assert exc.value.reason is Reason.ANALYSIS_TIMEOUT
    assert time.monotonic() - started < 3


def test_cpu_limit_stops_a_spinning_worker():
    started = time.monotonic()
    with pytest.raises(Rejected) as exc:
        run(Isolator(Limits(cpu_s=1, wall_s=15)), spin, Names)
    assert exc.value.reason is Reason.ANALYSIS_TIMEOUT
    assert time.monotonic() - started < 8


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced on Linux only")
def test_memory_limit_stops_a_hog(isolator):
    with pytest.raises(Rejected) as exc:
        run(isolator, hog_memory, Names)
    assert exc.value.reason is Reason.INPUT_TOO_LARGE


def test_worker_errors_carry_no_input_back(isolator):
    with pytest.raises(RuntimeError) as exc:
        run(isolator, crash_with_input, Names, "secret-input-text")
    assert "secret-input-text" not in str(exc.value)
    with pytest.raises(RuntimeError):
        run(isolator, die, Names)


def test_hosted_analysis_over_the_deadline_is_a_clean_422(make_hosted, providers, monkeypatch):
    monkeypatch.setattr(forensics_api, "analyze_url", sleep_forever)
    client = make_hosted(analysis_wall_s=0.5)
    sign_in(client, providers)
    started = time.monotonic()
    resp = client.post("/api/forensics/url", json={"url": "https://a.example/"}, headers=csrf(client))
    assert resp.status_code == 422 and resp.json()["reason"] == "analysis_timeout"
    assert resp.headers["strict-transport-security"]
    assert time.monotonic() - started < 3
    # The slot is released: the next request is served.
    monkeypatch.undo()
    assert (
        client.post("/api/forensics/url", json={"url": "https://a.example/"}, headers=csrf(client)).status_code == 200
    )
