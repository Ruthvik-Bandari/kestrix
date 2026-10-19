# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted mode: run each analysis in its own resource-limited worker process.

The hosted service parses strangers' files and emails. A parser that burns CPU or memory on a
crafted input must not take the shared server with it, so every hosted analysis (email check,
file forensics, URL forensics) runs in a fresh process forked from a ``multiprocessing`` fork
server:

- The worker gets only the input bytes and the analysis options, pickled by the trusted parent.
  It sends back JSON (the report's ``model_dump``, or a rejection), never a pickle, and the parent
  validates it against the expected report model, so a compromised worker cannot run code in
  the server.
- The fork server is started once, before the server accepts requests, with a minimal
  environment (``PATH``, locale, time zone and temp directory only). Workers therefore never see
  the session pepper, the OAuth client secrets or the log salt. (``kestrix serve-hosted`` also drops
  those variables from its own environment, so a fork server that multiprocessing restarts later
  starts without them too.)
- In the worker: ``RLIMIT_CPU`` (the kernel stops it after ``cpu_s`` seconds of CPU), no core
  dumps, and on Linux ``RLIMIT_AS`` (address space). macOS does not enforce ``RLIMIT_AS``, so
  it is not set there.
- In the parent: a wall-clock deadline. A worker still running at ``wall_s`` is killed and the
  request gets ``analysis_timeout`` (HTTP 422: the input needs more work than the service
  allows; retrying the same input will not help).

Local mode does not use this module; it analyzes in-process as before.
"""

from __future__ import annotations

import contextlib
import json
import multiprocessing
import os
import signal
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, TypeVar

import anyio
from pydantic import BaseModel

from ..core.errors import Reason, Rejected

MIB = 1024 * 1024
MAX_RESULT_BYTES = 16 * MIB
# The only variables the fork server, and so every worker, inherits.
ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR")
# Imported once in the fork server, so each worker starts without import work. multiprocessing
# also re-runs the server's entry script in every worker (it must be import-safe, as console
# scripts are); "kestrix.cli" is preloaded so that re-run of ``kestrix serve-hosted`` is cheap.
PRELOAD = [
    "kestrix.cli",
    "kestrix.server.isolation",
    "kestrix.mail.analyze",
    "kestrix.forensics.api",
    "kestrix.forensics.url",
]
TIMEOUT_DETAIL = "the analysis took too long and was stopped; the input may be too complex to check here"

Model = TypeVar("Model", bound=BaseModel)


@dataclass(frozen=True)
class Limits:
    cpu_s: int = 10
    memory_bytes: int = 384 * MIB
    wall_s: float = 20.0


@contextlib.contextmanager
def _minimal_environ() -> Iterator[None]:
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update({name: saved[name] for name in ENV_ALLOWLIST if name in saved})
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _apply_limits(limits: Limits) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_s, limits.cpu_s + 1))
    if sys.platform.startswith("linux"):  # macOS accepts RLIMIT_AS but does not enforce it
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))


def _worker(
    conn: Connection, fn: Callable[..., BaseModel], args: tuple[Any, ...], kwargs: dict[str, Any], limits: Limits
) -> None:
    """Runs in the worker process: apply the limits, analyze, send JSON back."""
    # The fork server starts with a minimal environment, but imports or the platform can add
    # variables afterwards (Linux CI showed COLUMNS and LINES). Filter again, so nothing outside the
    # allowlist reaches the analysis whatever its origin.
    for name in [name for name in os.environ if name not in ENV_ALLOWLIST]:
        del os.environ[name]
    _apply_limits(limits)
    message: dict[str, Any]
    try:
        message = {"ok": fn(*args, **kwargs).model_dump(mode="json")}
    except Rejected as exc:
        message = {"rejected": exc.reason.value, "detail": exc.detail}
    except MemoryError:
        message = {"rejected": Reason.INPUT_TOO_LARGE.value, "detail": "the analysis needs more memory than allowed"}
    except Exception:  # never send a traceback (it may quote the input) back
        message = {"error": "internal"}
    conn.send_bytes(json.dumps(message).encode())
    conn.close()


class Isolator:
    """Runs ``fn(*args, **kwargs)`` in a limited worker and returns its report as ``model``."""

    def __init__(self, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        self._ctx = multiprocessing.get_context("forkserver")

    def start(self) -> None:
        """Start the fork server with a minimal environment. Call before serving requests, while
        the process has one thread, because it briefly replaces ``os.environ``."""
        from multiprocessing import forkserver

        self._ctx.set_forkserver_preload(PRELOAD)
        with _minimal_environ():
            forkserver.ensure_running()

    async def run(self, fn: Callable[..., BaseModel], model: type[Model], *args: Any, **kwargs: Any) -> Model:
        message = await anyio.to_thread.run_sync(self._run_blocking, fn, args, kwargs)
        if "ok" in message:
            return model.model_validate(message["ok"])
        if "rejected" in message:
            raise Rejected(Reason(message["rejected"]), str(message.get("detail", ""))[:1000])
        raise RuntimeError("analysis worker failed")

    def _run_blocking(
        self, fn: Callable[..., BaseModel], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.limits.wall_s
        receiver, sender = self._ctx.Pipe(duplex=False)
        proc = self._ctx.Process(target=_worker, args=(sender, fn, args, kwargs, self.limits), daemon=True)
        try:
            proc.start()
            sender.close()
            if not receiver.poll(max(0.0, deadline - time.monotonic())):
                raise Rejected(Reason.ANALYSIS_TIMEOUT, TIMEOUT_DETAIL)
            try:
                data = receiver.recv_bytes(MAX_RESULT_BYTES)
            except EOFError:  # the worker died without answering
                proc.join(1)
                if proc.exitcode in {-signal.SIGXCPU, -signal.SIGKILL}:
                    raise Rejected(Reason.ANALYSIS_TIMEOUT, TIMEOUT_DETAIL) from None
                raise RuntimeError(f"analysis worker exited with {proc.exitcode}") from None
            message = json.loads(data)
            if not isinstance(message, dict):
                raise RuntimeError("analysis worker sent a malformed result")
            return message
        finally:
            receiver.close()
            sender.close()
            if proc.pid is not None:
                if proc.is_alive():
                    proc.kill()
                proc.join(5)
                proc.close()
