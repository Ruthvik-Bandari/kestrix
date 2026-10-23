# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix mail`` commands. Exit codes: 0 done, 2 rejected input or a failed connection."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Annotated

import typer

from ..core.errors import Reason, Rejected
from .analyze import analyze_stream
from .mailbox import MailboxService
from .mailbox.loopback import connect_with_loopback
from .mailbox.models import NETWORK_NOTICE, Provider
from .mailbox.store import PROVIDERS
from .models import NOTICE, MailReport
from .parse import MAX_MESSAGE_BYTES

app = typer.Typer(no_args_is_help=True)

_WIDTH = 100


@app.callback()
def _group() -> None:
    """Explainable analysis of saved email messages (.eml); connect a mailbox to pick messages from it."""


@app.command("analyze")
def analyze_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Saved message (.eml); never rendered.")],
    protected_domain: Annotated[
        list[str] | None,
        typer.Option(
            "--protected-domain", help="Domain to protect from display-name and look-alike impersonation; repeatable."
        ),
    ] = None,
    trusted_authserv_id: Annotated[
        list[str] | None,
        typer.Option("--trusted-authserv-id", help="authserv-id of your mail provider; repeatable."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Check a saved message's authentication, sender, look-alike domains, links, attachments and wording offline."""
    try:
        if path.stat().st_size > MAX_MESSAGE_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"message is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
        with path.open("rb") as stream:
            report = analyze_stream(
                stream,
                protected_domains=frozenset(protected_domain or ()),
                trusted_authserv_ids=frozenset(trusted_authserv_id or ()),
            )
    except Rejected as exc:
        typer.echo(f"Rejected ({exc.reason.value}): {exc.detail}", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(report.model_dump_json(indent=2) if as_json else render(report))


def _fail(exc: Rejected) -> typer.Exit:
    typer.echo(f"Rejected ({exc.reason.value}): {exc.detail}", err=True)
    return typer.Exit(code=2)


@app.command("connect")
def connect_command(
    provider: Annotated[Provider, typer.Argument(help="gmail or outlook.")],
    client_id: Annotated[str, typer.Option("--client-id", help="Client ID of your own OAuth app registration.")],
    client_secret: Annotated[
        str | None,
        typer.Option(
            "--client-secret",
            envvar="KESTRIX_MAIL_CLIENT_SECRET",
            help="Gmail Desktop app client secret (not used for Outlook). Prefer the environment variable: "
            "command lines land in shell history.",
        ),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", help="Outlook only: common (default), organizations, consumers, or a tenant ID."),
    ] = None,
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Print the sign-in address instead of opening it.")
    ] = False,
) -> None:
    """Connect a Gmail or Outlook mailbox (read-only) using your own OAuth app. Local use only."""
    service = MailboxService()
    try:
        service.configure(provider, client_id, client_secret, tenant)
        typer.echo(NETWORK_NOTICE)
        status = connect_with_loopback(service, provider, typer.echo, open_browser=not no_browser)
    except Rejected as exc:
        raise _fail(exc) from None
    typer.echo(
        f"Connected {status.label}{f' as {status.account}' if status.account else ''}. Kestrix can read mail but never changes it."
    )


@app.command("disconnect")
def disconnect_command(
    provider: Annotated[Provider, typer.Argument(help="gmail or outlook.")],
    forget_app: Annotated[
        bool, typer.Option("--forget-app", help="Also delete the stored client ID and secret.")
    ] = False,
) -> None:
    """Delete the saved sign-in and revoke it where the provider supports that."""
    try:
        result = MailboxService().disconnect(provider, forget_app=forget_app)
    except Rejected as exc:
        raise _fail(exc) from None
    typer.echo(result.detail)


@app.command("status")
def status_command() -> None:
    """Show which mailboxes are configured and connected (no secrets are printed)."""
    for status in MailboxService().status().providers:
        state = (
            f"connected as {status.account or 'unknown account'}"
            if status.connected
            else ("app configured, not connected" if status.configured else "not configured")
        )
        typer.echo(f"{status.provider}: {state}")
    typer.echo(f"Providers: {', '.join(PROVIDERS)}")


def render(report: MailReport) -> str:
    lines = [
        f"From:     {report.from_address or '(none)'}",
        f"Subject:  {report.subject or '(none)'}",
        f"SHA-256:  {report.sha256}",
        f"Verdict:  {report.verdict} (heuristic score {report.heuristic_score}/100)",
        f"Parts:    {report.counts.parts}, links {report.counts.links}, attachments {report.counts.attachments}",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.append("Findings:")
        for finding in report.findings:
            lines.append(f"  [{finding.severity.upper()}] {finding.title}")
            lines.append(textwrap.fill(finding.explanation, _WIDTH, initial_indent=" " * 6, subsequent_indent=" " * 6))
            if finding.evidence:
                lines.append(f"      evidence: {finding.evidence}")
    return "\n".join([*lines, "", textwrap.fill(NOTICE, _WIDTH)])
