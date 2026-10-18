"""``kestrix mail`` commands. Exit codes: 0 analysed, 2 rejected input."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Annotated

import typer

from ..core.errors import Reason, Rejected
from .analyze import analyze_stream
from .models import NOTICE, MailReport
from .parse import MAX_MESSAGE_BYTES

app = typer.Typer(no_args_is_help=True)

_WIDTH = 100


@app.callback()
def _group() -> None:
    """Explainable analysis of saved email messages (.eml)."""


@app.command("analyze")
def analyze_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Saved message (.eml); never rendered.")],
    protected_domain: Annotated[
        list[str] | None,
        typer.Option("--protected-domain", help="Domain to protect from display-name impersonation; repeatable."),
    ] = None,
    trusted_authserv_id: Annotated[
        list[str] | None,
        typer.Option("--trusted-authserv-id", help="authserv-id of your mail provider; repeatable."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Check a saved message's authentication, sender, links and attachments offline."""
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
