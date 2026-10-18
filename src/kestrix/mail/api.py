"""HTTP endpoint for saved-message analysis.

The upload is parsed straight from the request stream with a running byte count, as in
``forensics/api.py``, so an oversized body is refused while it arrives. The message lands in
an anonymous SpooledTemporaryFile and is only ever read.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import APIRouter, Query, Request
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from ..core.errors import Reason, Rejected
from .analyze import analyze_stream
from .models import MailReport
from .parse import MAX_MESSAGE_BYTES

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


@router.post("/analyze", openapi_extra=_UPLOAD_BODY)
async def analyze_upload(
    request: Request,
    protected_domain: Annotated[
        list[str] | None, Query(description="Domain to protect from display-name impersonation; repeat up to 20 times.")
    ] = None,
    trusted_authserv_id: Annotated[
        list[str] | None, Query(description="authserv-id of your mail provider; repeat up to 5 times.")
    ] = None,
) -> MailReport:
    """Offline analysis of one saved message (.eml) uploaded as multipart field ``file``."""
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise Rejected(Reason.INVALID_INPUT, "send the message as multipart/form-data in a field named 'file'")
    limit = MAX_MESSAGE_BYTES + _MULTIPART_OVERHEAD
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
    parser = MultiPartParser(request.headers, _capped(request, limit), max_files=1, max_fields=0)
    try:
        form = await parser.parse()
    except MultiPartException as exc:
        raise Rejected(Reason.INVALID_INPUT, exc.message) from None
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise Rejected(Reason.INVALID_INPUT, "the multipart body has no file field named 'file'")
        return await run_in_threadpool(
            analyze_stream,
            upload.file,
            protected_domains=frozenset(protected_domain or ()),
            trusted_authserv_ids=frozenset(trusted_authserv_id or ()),
        )
    finally:
        await form.close()


async def _capped(request: Request, limit: int) -> AsyncGenerator[bytes, None]:
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
        yield chunk
