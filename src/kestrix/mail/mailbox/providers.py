# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Gmail API and Microsoft Graph adapters: list and search, fetch one raw message, read the account label.

Read-only: every call is a GET with a read-only scope. Row text is cleaned and cut to a fixed length here, so
nothing longer than a subject or a 120-character snippet ever leaves this module.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, ClassVar, Protocol
from urllib.parse import quote, urlencode

from ...core.errors import RateLimited, Reason, Rejected
from ..parse import MAX_MESSAGE_BYTES
from .http import MailboxHttp, Reply
from .models import MAX_FIELD_CHARS, MAX_SNIPPET_CHARS, MessageSummary, SearchParams, SearchResult

GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
GRAPH_API = "https://graph.microsoft.com/v1.0/me"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GRAPH_SCOPE = "https://graph.microsoft.com/Mail.Read"
MESSAGE_ID = re.compile(r"[A-Za-z0-9_=+-]{1,512}")
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]+")
_GMAIL_RATE_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded"})
_REASON = re.compile(r"[A-Za-z]{1,64}")
DEFAULT_RETRY_S = 30
MAX_RETRY_S = 3600
METADATA_WORKERS = 4
# Gmail returns base64url, so the answer is about 4/3 of the message plus JSON framing.
GMAIL_RAW_LIMIT = MAX_MESSAGE_BYTES * 4 // 3 + 64 * 1024
GRAPH_NEXT_PREFIX = f"{GRAPH_API}/"


class Unauthorized(Exception):
    """The provider answered 401: the access token is expired or revoked."""


def clean(text: object, limit: int) -> str:
    """Single-line text without control or bidi-override characters, cut to ``limit`` characters."""
    if not isinstance(text, str):
        return ""
    return " ".join(_CONTROL.sub(" ", text).split())[:limit]


def _retry_after(reply: Reply) -> int:
    value = reply.headers.get("retry-after", "")
    return min(int(value), MAX_RETRY_S) if value.isdigit() else DEFAULT_RETRY_S


def _error_reason(reply: Reply) -> str:
    """The short `reason` code from a Google error body, or ''. Provider messages are not repeated."""
    try:
        body = json.loads(reply.body)
        reason = body["error"]["errors"][0]["reason"]
    except (ValueError, KeyError, IndexError, TypeError):
        return ""
    return reason if isinstance(reason, str) and _REASON.fullmatch(reason) else ""


def check_reply(reply: Reply, who: str) -> Reply:
    """Pass a 2xx answer through; turn every other status into an explicit outcome."""
    if 200 <= reply.status < 300:
        return reply
    if reply.status == 401:
        raise Unauthorized
    if reply.status == 429:
        raise RateLimited(f"{who} is limiting requests; try again later", _retry_after(reply))
    if reply.status == 403:
        reason = _error_reason(reply)
        if reason in _GMAIL_RATE_REASONS:
            raise RateLimited(f"{who} is limiting requests; try again later", _retry_after(reply))
        if reason == "accessNotConfigured":
            raise Rejected(
                Reason.UPSTREAM_ERROR,
                "the Gmail API is not enabled in your Google Cloud project; enable it and try again",
            )
        raise Rejected(
            Reason.UPSTREAM_ERROR,
            f"{who} refused the request (403); check that the app has read-only mail access and your account is a test user",
        )
    if reply.status == 404:
        raise Rejected(Reason.INVALID_INPUT, "that message was not found; it may have been deleted or moved")
    raise Rejected(Reason.UPSTREAM_ERROR, f"{who} answered with status {reply.status}")


def _json(reply: Reply) -> dict[str, Any]:
    try:
        body = json.loads(reply.body)
    except ValueError:
        raise Rejected(Reason.UPSTREAM_ERROR, "the provider's answer was not valid JSON") from None
    if not isinstance(body, dict):
        raise Rejected(Reason.UPSTREAM_ERROR, "the provider's answer had an unexpected shape")
    return body


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def validate_message_id(message_id: str) -> str:
    if not MESSAGE_ID.fullmatch(message_id):
        raise Rejected(Reason.INVALID_INPUT, "message_id is not a valid message id")
    return message_id


class ProviderApi(Protocol):
    def search(self, http: MailboxHttp, token: str, params: SearchParams) -> SearchResult: ...

    def fetch_raw(self, http: MailboxHttp, token: str, message_id: str) -> bytes: ...

    def account_label(self, http: MailboxHttp, token: str) -> str | None: ...


class Gmail:
    def search(self, http: MailboxHttp, token: str, params: SearchParams) -> SearchResult:
        limit = params.limit
        pairs: list[tuple[str, str]] = [("maxResults", str(limit))]
        if params.query:
            pairs.append(("q", params.query))
        if params.folder == "inbox":
            pairs.append(("labelIds", "INBOX"))
        elif params.folder == "junk":
            pairs += [("labelIds", "SPAM"), ("includeSpamTrash", "true")]
        if params.page_token:
            pairs.append(("pageToken", params.page_token))
        listing = _json(
            check_reply(
                http.request("GET", f"{GMAIL_API}/messages?{urlencode(pairs)}", headers=_bearer(token)), "Google"
            )
        )
        ids = [m["id"] for m in listing.get("messages", []) if isinstance(m, dict) and isinstance(m.get("id"), str)]
        ids = [i for i in ids if MESSAGE_ID.fullmatch(i)][:limit]
        with ThreadPoolExecutor(max_workers=METADATA_WORKERS) as pool:
            rows = list(pool.map(lambda i: self._row(http, token, i), ids))
        next_token = listing.get("nextPageToken")
        return SearchResult(
            messages=[row for row in rows if row is not None],
            next_page_token=next_token if isinstance(next_token, str) and 0 < len(next_token) <= 2048 else None,
        )

    def _row(self, http: MailboxHttp, token: str, message_id: str) -> MessageSummary | None:
        query = urlencode(
            [("format", "metadata"), ("metadataHeaders", "From"), ("metadataHeaders", "Subject"),
             ("fields", "id,snippet,internalDate,payload/headers")]
        )  # fmt: skip
        reply = http.request(
            "GET", f"{GMAIL_API}/messages/{quote(message_id, safe='')}?{query}", headers=_bearer(token)
        )
        if reply.status == 404:  # deleted between the list and this call
            return None
        message = _json(check_reply(reply, "Google"))
        payload = message.get("payload")
        raw_headers = payload.get("headers", []) if isinstance(payload, dict) else []
        headers = {str(h.get("name", "")).lower(): h.get("value", "") for h in raw_headers if isinstance(h, dict)}
        date: str | None = None
        internal = message.get("internalDate")
        if isinstance(internal, str) and internal.isdigit() and len(internal) <= 14:
            date = datetime.fromtimestamp(int(internal) / 1000, tz=timezone.utc).isoformat()
        return MessageSummary(
            id=message_id,
            sender=clean(headers.get("from"), MAX_FIELD_CHARS),
            subject=clean(headers.get("subject"), MAX_FIELD_CHARS),
            date=date,
            snippet=clean(html.unescape(str(message.get("snippet", ""))), MAX_SNIPPET_CHARS),
        )

    def fetch_raw(self, http: MailboxHttp, token: str, message_id: str) -> bytes:
        quoted = quote(validate_message_id(message_id), safe="")
        meta = _json(
            check_reply(
                http.request(
                    "GET", f"{GMAIL_API}/messages/{quoted}?format=minimal&fields=sizeEstimate", headers=_bearer(token)
                ),
                "Google",
            )
        )
        size = meta.get("sizeEstimate")
        if isinstance(size, int) and size > MAX_MESSAGE_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"the message is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
        reply = http.request(
            "GET",
            f"{GMAIL_API}/messages/{quoted}?format=raw&fields=raw",
            headers=_bearer(token),
            max_bytes=GMAIL_RAW_LIMIT,
            too_large=Reason.INPUT_TOO_LARGE,
        )
        raw = _json(check_reply(reply, "Google")).get("raw")
        if not isinstance(raw, str):
            raise Rejected(Reason.UPSTREAM_ERROR, "Google returned no message content")
        try:
            data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (binascii.Error, ValueError):
            raise Rejected(Reason.UPSTREAM_ERROR, "Google returned message content that could not be decoded") from None
        if len(data) > MAX_MESSAGE_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"the message is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
        return data

    def account_label(self, http: MailboxHttp, token: str) -> str | None:
        reply = http.request("GET", f"{GMAIL_API}/profile?fields=emailAddress", headers=_bearer(token))
        address = _json(check_reply(reply, "Google")).get("emailAddress")
        return clean(address, MAX_FIELD_CHARS) or None


def _graph_from(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    address = value.get("emailAddress")
    if not isinstance(address, dict):
        return ""
    name, mail = clean(address.get("name"), MAX_FIELD_CHARS), clean(address.get("address"), MAX_FIELD_CHARS)
    return f"{name} <{mail}>" if name and mail and name != mail else (mail or name)


def encode_next_link(link: str) -> str | None:
    if not link.startswith(GRAPH_NEXT_PREFIX) or len(link) > 2048:
        return None
    return base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")


def decode_next_link(token: str) -> str:
    try:
        link = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise Rejected(Reason.INVALID_INPUT, "page_token is not valid") from None
    if not link.startswith(GRAPH_NEXT_PREFIX) or any(ch in link for ch in "\r\n\\ "):
        raise Rejected(Reason.INVALID_INPUT, "page_token is not valid")
    return link


class Graph:
    _FOLDERS: ClassVar[dict[str, str]] = {
        "inbox": "/mailFolders/inbox/messages",
        "junk": "/mailFolders/junkemail/messages",
        "all": "/messages",
    }

    def search(self, http: MailboxHttp, token: str, params: SearchParams) -> SearchResult:
        if params.page_token:
            url = decode_next_link(params.page_token)
        else:
            pairs = [("$select", "id,subject,from,receivedDateTime,bodyPreview"), ("$top", str(params.limit))]
            if params.query:
                escaped = params.query.replace("\\", "\\\\").replace('"', '\\"')
                pairs.append(("$search", f'"{escaped}"'))
            else:
                pairs.append(("$orderby", "receivedDateTime desc"))
            query = "&".join(f"{key}={quote(value, safe='$,')}" for key, value in pairs)
            url = f"{GRAPH_API}{self._FOLDERS[params.folder]}?{query}"
        body = _json(check_reply(http.request("GET", url, headers=_bearer(token)), "Microsoft"))
        rows: list[MessageSummary] = []
        for item in body.get("value", []):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not MESSAGE_ID.fullmatch(item["id"])
            ):
                continue
            received = item.get("receivedDateTime")
            rows.append(
                MessageSummary(
                    id=item["id"],
                    sender=_graph_from(item.get("from")),
                    subject=clean(item.get("subject"), MAX_FIELD_CHARS),
                    date=received if isinstance(received, str) and len(received) <= 40 else None,
                    snippet=clean(item.get("bodyPreview"), MAX_SNIPPET_CHARS),
                )
            )
        link = body.get("@odata.nextLink")
        return SearchResult(
            messages=rows[: params.limit], next_page_token=encode_next_link(link) if isinstance(link, str) else None
        )

    def fetch_raw(self, http: MailboxHttp, token: str, message_id: str) -> bytes:
        quoted = quote(validate_message_id(message_id), safe="")
        reply = http.request(
            "GET",
            f"{GRAPH_API}/messages/{quoted}/$value",
            headers={"Authorization": f"Bearer {token}"},
            max_bytes=MAX_MESSAGE_BYTES,
            too_large=Reason.INPUT_TOO_LARGE,
        )
        return check_reply(reply, "Microsoft").body

    def account_label(self, http: MailboxHttp, token: str) -> str | None:
        return None


def id_token_label(id_token: object) -> str | None:
    """Display label from an OIDC id_token's payload. Not verified and used for display only."""
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        return None
    segment = id_token.split(".")[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (binascii.Error, ValueError):
        return None
    if not isinstance(claims, dict):
        return None
    return clean(claims.get("preferred_username") or claims.get("email"), MAX_FIELD_CHARS) or None


API: dict[str, ProviderApi] = {"gmail": Gmail(), "outlook": Graph()}
