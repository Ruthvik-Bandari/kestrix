# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from kestrix.core.errors import Reason, Rejected
from kestrix.forensics.api import router


def _router_only_app() -> FastAPI:
    """This router with the same Rejected -> HTTP mapping the platform app uses for these reasons."""
    app = FastAPI()
    app.include_router(router)

    @app.exception_handler(Rejected)
    async def _rejected(_: Request, exc: Rejected) -> JSONResponse:
        status = 413 if exc.reason is Reason.INPUT_TOO_LARGE else 400
        return JSONResponse({"reason": exc.reason.value, "detail": exc.detail}, status_code=status)

    return app


@pytest.fixture
def client() -> TestClient:
    try:
        from kestrix.server.app import create_app
    except ImportError:  # sibling modules may not exist yet; exercise this router on its own
        return TestClient(_router_only_app())
    return TestClient(create_app(extra_hosts=frozenset({"testserver"})))
