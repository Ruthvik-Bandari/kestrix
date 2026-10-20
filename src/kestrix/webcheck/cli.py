# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix webcheck`` command. Exit codes: 0 ok, 2 rejected input or target, 3 unreachable."""

from __future__ import annotations

import typer

from ..core.enums import TextEnum
from ..core.errors import Reason, Rejected
from .models import NOTICE
from .scan import scan

app = typer.Typer(no_args_is_help=True)

_UNREACHABLE = frozenset({Reason.TARGET_UNREACHABLE, Reason.UPSTREAM_ERROR})


class SiteType(TextEnum):
    static = "static"
    static_api = "static_api"
    dynamic = "dynamic"


@app.callback()
def _group() -> None:
    """Passive web exposure checks."""


@app.command("scan")
def scan_cmd(
    url: str,
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow private or loopback targets you own."),
    as_json: bool = typer.Option(False, "--json"),
    site_type: SiteType | None = typer.Option(
        None, "--site-type", help="What you know the site is; it can raise, never lower, the detected profile."
    ),
) -> None:
    """Passively check a website's HTTPS, TLS, security headers and cookies."""
    if not as_json:
        typer.echo(NOTICE)
    try:
        report = scan(url, allow_private=allow_private, site_type=site_type.value if site_type else None)
    except Rejected as exc:
        typer.echo(f"error: {exc.reason}: {exc.detail}", err=True)
        raise typer.Exit(3 if exc.reason in _UNREACHABLE else 2) from None
    if as_json:
        typer.echo(report.model_dump_json(indent=2))
        return
    typer.echo(f"\n{report.final_url}  grade {report.grade} ({report.score}/100)  TLS: {report.tls.status}")
    if report.profile:
        typer.echo(f"site profile: {report.profile.kind} ({'; '.join(report.profile.reasons)})")
    for f in report.findings:
        typer.echo(f"  [{f.severity:<6}] {f.title}\n           fix: {f.recommendation}")
        if f.context:
            typer.echo(f"           why {f.severity}: {f.context}")
