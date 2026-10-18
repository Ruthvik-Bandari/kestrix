# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP route for the passive web exposure check."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from ..core.errors import Reason, Rejected
from .models import Report
from .profile import SiteKind
from .scan import scan

router = APIRouter(prefix="/api/webcheck", tags=["webcheck"])


class ScanBody(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    allow_private: bool = Field(
        default=False, description="Allow private/loopback targets such as a lab server you own."
    )
    site_type: SiteKind | None = Field(
        default=None,
        description="What the owner knows the site is (static, static_api, dynamic). It can raise, never lower, the detected profile.",
    )


@router.post("", response_model=Report)
def webcheck(body: ScanBody) -> Report:
    return scan(body.url, allow_private=body.allow_private, site_type=body.site_type)


class HostedScanBody(ScanBody):
    model_config = ConfigDict(extra="forbid")

    authorized: bool = Field(
        default=False, description="Required on the hosted service: I own or am authorized to test this site."
    )


def hosted_router(agent: str) -> APIRouter:
    """The hosted-service variant: public targets only, an authorization confirmation per scan,
    and a User-Agent that names an abuse contact."""
    hosted = APIRouter(prefix="/api/webcheck", tags=["webcheck"])

    @hosted.post("", response_model=Report)
    def webcheck_hosted(body: HostedScanBody) -> Report:
        if body.allow_private:
            raise Rejected(Reason.INVALID_INPUT, "the hosted service checks public websites only")
        if not body.authorized:
            raise Rejected(Reason.INVALID_INPUT, "confirm that you own or are authorized to test this site")
        return scan(body.url, allow_private=False, site_type=body.site_type, agent=agent)

    return hosted
