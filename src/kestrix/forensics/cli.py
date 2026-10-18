# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix forensics`` commands: plain-text summaries by default, full JSON with --json."""

import textwrap
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from ..core.errors import Rejected
from .analysis import analyze_file
from .models import FileReport, Finding, UrlReport
from .url import analyze_url

app = typer.Typer(no_args_is_help=True)

_WIDTH = 100
_EXIF_STATUS = {
    "no_exif": "none in this image",
    "not_image": "not applicable (not an image format that carries EXIF)",
    "pillow_not_installed": "not read; install kestrix[exif] to enable it",
    "unreadable": "present but could not be parsed",
    "too_many_pixels": "not read; the image declares implausibly large dimensions",
}


@app.command("file")
def file_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="File to analyse; never executed.")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Hash a file, measure its entropy, identify its real format and read image metadata."""
    try:
        with path.open("rb") as stream:
            report = analyze_file(stream, path.name)
    except Rejected as exc:
        _reject(exc)
    typer.echo(report.model_dump_json(indent=2) if as_json else render_file(report))


@app.command("url")
def url_command(
    url: Annotated[str, typer.Argument(help="URL to check; it is analysed as text and never visited.")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Score a URL with offline phishing heuristics."""
    try:
        report = analyze_url(url)
    except Rejected as exc:
        _reject(exc)
    typer.echo(report.model_dump_json(indent=2) if as_json else render_url(report))


def render_file(report: FileReport) -> str:
    kind = report.file_type
    entropy = report.entropy
    mismatch = "  [extension does not match the content]" if kind.extension_mismatch else ""
    lines = [
        f"File:     {report.filename} ({report.size:,} bytes)",
        f"Type:     {kind.label}{mismatch}",
        f"MD5:      {report.hashes.md5}",
        f"SHA-1:    {report.hashes.sha1}",
        f"SHA-256:  {report.hashes.sha256}",
        f"SHA-512:  {report.hashes.sha512}",
        f"Entropy:  {entropy.overall:.3f} bits per byte (0 = one repeated byte, 8 = looks random)",
        f"Random-looking regions: {entropy.high_entropy_region_count} ({entropy.high_entropy_bytes:,} bytes)",
        f"Printable text: {report.printable_ratio:.0%} of bytes",
        f"EXIF:     {_exif_summary(report)}",
    ]
    return "\n".join([*lines, "", *_render_findings(report.findings)])


def render_url(report: UrlReport) -> str:
    shown = f" (displayed as {report.unicode_host})" if report.unicode_host != report.host else ""
    lines = [
        f"URL:      {report.url}",
        f"Host:     {report.host}{shown}",
        f"Score:    {report.score}/100 ({report.level})",
        textwrap.fill(report.score_note, _WIDTH),
    ]
    return "\n".join([*lines, "", *_render_findings(report.findings)])


def _exif_summary(report: FileReport) -> str:
    if report.exif is None:
        return _EXIF_STATUS[report.exif_status]
    gps = ", including GPS location" if report.exif.gps_present else ""
    return f"{len(report.exif.tags)} tag(s){gps}"


def _render_findings(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No findings."]
    lines = ["Findings:"]
    for finding in findings:
        lines.append(f"  [{finding.severity.upper()}] {finding.title}")
        lines.append(textwrap.fill(finding.explanation, _WIDTH, initial_indent=" " * 6, subsequent_indent=" " * 6))
    return lines


def _reject(exc: Rejected) -> NoReturn:
    typer.echo(f"Rejected ({exc.reason.value}): {exc.detail}", err=True)
    raise typer.Exit(code=2)
