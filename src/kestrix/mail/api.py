# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP endpoint for saved-message analysis.

The upload is parsed straight from the request stream with a running byte count, as in
``forensics/api.py``, so an oversized body is refused while it arrives. The message lands in
an anonymous SpooledTemporaryFile and is only ever read.

``hosted_router`` is the hosted-service variant: a lower upload cap, and each analysis runs in
a resource-limited worker process (``server/isolation.py``).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Query, Request
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from ..core.errors import Reason, Rejected
from .analyze import analyze, analyze_stream
from .models import MailReport
from .parse import MAX_MESSAGE_BYTES

if TYPE_CHECKING:
    from ..server.isolation import Isolator

router = APIRouter(prefix="/api/mail", tags=["mail"])

# Room for the multipart boundary and part headers around the message itself.
_MULTIPART_OVERHEAD = 64 * 1024
_UPLOAD_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string", "format": "binary"}},
                },
            },
        },
    },
}


ProtectedDomains = Annotated[
    list[str] | None,
    Query(description="Domain to protect from display-name and look-alike impersonation; repeat up to 20 times."),
]
TrustedAuthservIds = Annotated[
    list[str] | None, Query(description="authserv-id of your mail provider; repeat up to 5 times.")
]


@router.post("/analyze", openapi_extra=_UPLOAD_BODY)
async def analyze_upload(
    request: Request, protected_domain: ProtectedDomains = None, trusted_authserv_id: TrustedAuthservIds = None
) -> MailReport:
    """Offline analysis of one saved message (.eml) uploaded as multipart field ``file``."""
    async with _upload(request, MAX_MESSAGE_BYTES) as upload:
        return await run_in_threadpool(
            analyze_stream,
            upload.file,
            protected_domains=frozenset(protected_domain or ()),
            trusted_authserv_ids=frozenset(trusted_authserv_id or ()),
        )


@asynccontextmanager
async def _upload(request: Request, max_bytes: int) -> AsyncIterator[UploadFile]:
    """The multipart field ``file``, parsed from the stream with a running byte count."""
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise Rejected(Reason.INVALID_INPUT, "send the message as multipart/form-data in a field named 'file'")
    limit = max_bytes + _MULTIPART_OVERHEAD
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {max_bytes:,} byte limit")
    parser = MultiPartParser(request.headers, _capped(request, limit, max_bytes), max_files=1, max_fields=0)
    try:
        form = await parser.parse()
    except MultiPartException as exc:
        raise Rejected(Reason.INVALID_INPUT, exc.message) from None
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise Rejected(Reason.INVALID_INPUT, "the multipart body has no file field named 'file'")
        yield upload
    finally:
        await form.close()


async def _capped(request: Request, limit: int, max_bytes: int) -> AsyncGenerator[bytes, None]:
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {max_bytes:,} byte limit")
        yield chunk


def hosted_router(isolator: Isolator, max_message_bytes: int) -> APIRouter:
    """The hosted-service route: messages capped at ``max_message_bytes``; every analysis runs in a
    limited worker process."""
    hosted = APIRouter(prefix="/api/mail", tags=["mail"])

    @hosted.post("/analyze", openapi_extra=_UPLOAD_BODY)
    async def analyze_upload_hosted(
        request: Request, protected_domain: ProtectedDomains = None, trusted_authserv_id: TrustedAuthservIds = None
    ) -> MailReport:
        """Offline analysis of one saved message (.eml) uploaded as multipart field ``file``."""
        async with _upload(request, max_message_bytes) as upload:
            raw = await run_in_threadpool(upload.file.read, max_message_bytes + 1)
        if len(raw) > max_message_bytes:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"message is larger than the {max_message_bytes:,} byte limit")
        return await isolator.run(
            analyze,
            MailReport,
            raw,
            protected_domains=frozenset(protected_domain or ()),
            trusted_authserv_ids=frozenset(trusted_authserv_id or ()),
        )

    return hosted
