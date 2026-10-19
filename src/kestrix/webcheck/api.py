# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""HTTP route for the passive web exposure check."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..core.errors import Reason, Rejected
from .models import Report
from .profile import SiteKind
from .scan import scan

router = APIRouter(prefix="/api/webcheck", tags=["webcheck"])
# The hosted service checks web servers only, on every hop.
HOSTED_PORTS = frozenset({80, 443})


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


def hosted_router(agent: str, audit: Callable[[Request, str], None]) -> APIRouter:
    """The hosted-service variant: public targets on ports 80 and 443 only, an authorization
    confirmation per scan, a User-Agent that names an abuse contact, one generic message for
    connection failures, and ``audit(request, url)`` called before each scan."""
    hosted = APIRouter(prefix="/api/webcheck", tags=["webcheck"])

    @hosted.post("", response_model=Report)
    def webcheck_hosted(body: HostedScanBody, request: Request) -> Report:
        if body.allow_private:
            raise Rejected(Reason.INVALID_INPUT, "the hosted service checks public websites only")
        if not body.authorized:
            raise Rejected(Reason.INVALID_INPUT, "confirm that you own or are authorized to test this site")
        audit(request, body.url)
        return scan(
            body.url,
            allow_private=False,
            site_type=body.site_type,
            agent=agent,
            allowed_ports=HOSTED_PORTS,
            generic_errors=True,
        )

    return hosted
