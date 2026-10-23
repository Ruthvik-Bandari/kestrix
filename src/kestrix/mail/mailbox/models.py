# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Response models of the local mailbox connector (ADR 0009).

A message row carries only what is needed to pick it: id, sender, subject, date and a short snippet.
Rows are shown in the page and are never stored or logged.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Provider = Literal["gmail", "outlook"]
Folder = Literal["inbox", "junk", "all"]

MAX_SNIPPET_CHARS = 120
MAX_FIELD_CHARS = 200
MAX_QUERY_CHARS = 200
MAX_PAGE_SIZE = 50

NETWORK_NOTICE = (
    "Connecting contacts Google or Microsoft from this computer (never from Kestrix servers). Kestrix asks for "
    "read-only access, never changes mail, and keeps only a refresh token on this computer."
)


class ProviderStatus(BaseModel):
    provider: Provider
    label: str = Field(description="Display name of the provider.")
    configured: bool = Field(description="A client id is stored. The client id and secret are never returned.")
    connected: bool = Field(description="A refresh token is stored.")
    account: str | None = Field(description="Account label (email address) shown after connecting.")
    scope: str = Field(description="The only scope requested: read-only mail access.")
    hosts: list[str] = Field(description="Hosts the dashboard contacts for this provider.")
    register_redirect_uri: str | None = Field(
        description="Redirect URI to register in your own app registration; null when the provider needs none."
    )


class MailboxStatus(BaseModel):
    notice: str = NETWORK_NOTICE
    providers: list[ProviderStatus]


class StartResult(BaseModel):
    authorize_url: str
    expires_in: int


class DisconnectResult(BaseModel):
    provider: Provider
    revoked: bool | None = Field(
        description="True: the provider confirmed the revoke. False: the call failed. None: no revoke call exists for this sign-in."
    )
    detail: str


class MessageSummary(BaseModel):
    id: str
    sender: str = Field(description="From header text, at most 200 characters.")
    subject: str = Field(description="Subject, at most 200 characters.")
    date: str | None = Field(description="ISO 8601 UTC time the message arrived.")
    snippet: str = Field(description="Preview text, at most 120 characters.")


class SearchResult(BaseModel):
    messages: list[MessageSummary]
    next_page_token: str | None


class SearchParams(BaseModel):
    """A validated list request: what to look for, where, and which page."""

    query: str
    folder: Folder
    page_token: str | None
    limit: int


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
