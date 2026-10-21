# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP routes for the result history (``/api/history``) and its on/off setting (ADR 0008).

Thin adapters over :class:`kestrix.server.history.HistoryStore`. ``user_of(request)`` names the
caller: the signed-in user on the hosted service (the gate has already required a session and, for
writes, the CSRF header), the single local user otherwise. Another user's row answers 404, exactly
like a missing one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException

from .history import RETENTION_DAYS, HistoryStore

MAX_PER_PAGE = 50
_ID = re.compile(r"[A-Za-z0-9_-]{22}")


class HistorySetting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _check_id(item_id: str) -> str:
    if not _ID.fullmatch(item_id):
        raise HTTPException(404, "no such result")
    return item_id


def history_router(history: HistoryStore, user_of: Callable[[Request], int]) -> APIRouter:
    router = APIRouter(tags=["history"])

    @router.get("/api/history")
    def list_history(
        request: Request,
        page: Annotated[int, Query(ge=1, le=100_000)] = 1,
        per_page: Annotated[int, Query(ge=1, le=MAX_PER_PAGE)] = 20,
    ) -> dict[str, Any]:
        """Your recent results, newest first: tool, time and a short verdict summary."""
        user_id = user_of(request)
        total, items = history.list(user_id, page, per_page)
        return {
            "enabled": history.enabled(user_id),
            "retention_days": RETENTION_DAYS,
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": [item.as_dict() for item in items],
        }

    @router.get("/api/history/{item_id}")
    def get_history(item_id: str, request: Request) -> dict[str, Any]:
        """One result with its full report."""
        found = history.get(user_of(request), _check_id(item_id))
        if found is None:
            raise HTTPException(404, "no such result")
        return found

    @router.delete("/api/history/{item_id}", status_code=204)
    def delete_history_item(item_id: str, request: Request) -> Response:
        if not history.delete(user_of(request), _check_id(item_id)):
            raise HTTPException(404, "no such result")
        return Response(status_code=204)

    @router.delete("/api/history", status_code=204)
    def delete_history(request: Request) -> Response:
        history.delete_all(user_of(request))
        return Response(status_code=204)

    @router.put("/api/settings/history")
    def set_history(body: HistorySetting, request: Request) -> dict[str, bool]:
        """Turn the history on or off. Off deletes every stored result and stops recording."""
        history.set_enabled(user_of(request), body.enabled)
        return {"enabled": body.enabled}

    return router
