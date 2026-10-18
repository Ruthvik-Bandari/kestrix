# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP endpoints for file and URL forensics.

Uploads are parsed straight from the request stream with a running byte count, so an
oversized body is refused while it arrives instead of after it has been spooled. File
data lands in an anonymous SpooledTemporaryFile (memory, then an unnamed temp file) and
is only ever read, never executed or written to a predictable path.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from ..core.errors import Reason, Rejected
from .analysis import MAX_FILE_BYTES, analyze_file
from .models import FileReport, UrlReport, UrlRequest
from .url import analyze_url

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

# Room for the multipart boundary and part headers around the file itself.
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


@router.post("/file", openapi_extra=_UPLOAD_BODY)
async def analyze_upload(request: Request) -> FileReport:
    """Hash, entropy, format and metadata analysis of one uploaded file (multipart field ``file``)."""
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise Rejected(Reason.INVALID_INPUT, "send the file as multipart/form-data in a field named 'file'")
    limit = MAX_FILE_BYTES + _MULTIPART_OVERHEAD
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {MAX_FILE_BYTES:,} byte limit")
    parser = MultiPartParser(request.headers, _capped(request, limit), max_files=1, max_fields=0)
    try:
        form = await parser.parse()
    except MultiPartException as exc:
        raise Rejected(Reason.INVALID_INPUT, exc.message) from None
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise Rejected(Reason.INVALID_INPUT, "the multipart body has no file field named 'file'")
        return await run_in_threadpool(analyze_file, upload.file, upload.filename or "upload")
    finally:
        await form.close()


@router.post("/url")
def analyze_url_endpoint(body: UrlRequest) -> UrlReport:
    """Offline phishing heuristics for a URL. The URL is never visited."""
    return analyze_url(body.url)


async def _capped(request: Request, limit: int) -> AsyncGenerator[bytes, None]:
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"upload is larger than the {MAX_FILE_BYTES:,} byte limit")
        yield chunk
