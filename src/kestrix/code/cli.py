# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix code`` commands. Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.

``--hook`` always exits 0: a scanner problem must never block the editor.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from ..core.errors import Rejected
from .analyze import FailOn, scan, write_baseline
from .analyze import exit_code as scan_exit_code
from .hook import MAX_STDIN_BYTES, hook_response
from .models import NOTICE, Finding, ScanReport
from .sarif import to_sarif

app = typer.Typer(no_args_is_help=True)

_COLORS = {
    "critical": typer.colors.BRIGHT_RED,
    "high": typer.colors.RED,
    "medium": typer.colors.YELLOW,
    "low": typer.colors.CYAN,
}


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    sarif = "sarif"


class FailLevel(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    none = "none"


@app.callback()
def _group() -> None:
    """Find security issues in source code (exits non-zero on findings)."""


@app.command("scan")
def scan_command(
    paths: Annotated[list[Path] | None, typer.Argument(help="Files or directories to scan. Default: '.'.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format", help="text, json or sarif.")] = OutputFormat.text,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write the report to this file instead of stdout.")
    ] = None,
    fail_on: Annotated[
        FailLevel, typer.Option("--fail-on", help="Lowest severity that makes the command exit 1; 'none' never fails.")
    ] = FailLevel.high,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="JSON list of fingerprints of known findings to leave out.")
    ] = None,
    new_baseline: Annotated[
        Path | None, typer.Option("--write-baseline", help="Write the current findings' fingerprints here and exit 0.")
    ] = None,
    diff: Annotated[
        str | None, typer.Option("--diff", help="Only report findings on lines changed since this git ref.")
    ] = None,
    hook: Annotated[
        bool, typer.Option("--hook", help="Claude Code PostToolUse mode: read the hook JSON on stdin; always exit 0.")
    ] = False,
) -> None:
    """Scan Python code for insecure patterns and any text file for hard-coded secrets."""
    if hook:
        _run_hook()
        return
    level: FailOn = fail_on.value
    try:
        report = scan(
            [str(p) for p in paths or [Path(".")]],
            fail_on=level,
            baseline=None if new_baseline else baseline,
            diff_base=diff,
        )
        if new_baseline is not None:
            written = write_baseline(new_baseline, report.findings)
            typer.echo(f"Wrote {written} fingerprint(s) to {new_baseline}.", err=True)
            return
    except Rejected as exc:
        typer.echo(f"Rejected ({exc.reason.value}): {exc.detail}", err=True)
        raise typer.Exit(code=2) from None
    rendered = _render(report, output_format, color=output is None and sys.stdout.isatty())
    if output is not None:
        try:
            output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            typer.echo(f"Rejected (invalid_input): cannot write {output}: {exc.strerror}", err=True)
            raise typer.Exit(code=2) from None
    else:
        typer.echo(rendered)
    raise typer.Exit(code=scan_exit_code(report))


def _run_hook() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES).decode("utf-8", "replace")
        response = hook_response(raw)
    except Exception as exc:  # fail open: never block the editor on a scanner problem
        typer.echo(f"kestrix code scan --hook: skipped ({type(exc).__name__})", err=True)
        return
    if response is not None:
        typer.echo(response)


def _render(report: ScanReport, output_format: OutputFormat, *, color: bool) -> str:
    if output_format is OutputFormat.json:
        return report.model_dump_json(indent=2)
    if output_format is OutputFormat.sarif:
        return json.dumps(to_sarif(report), indent=2)
    return render_text(report, color=color)


def render_text(report: ScanReport, *, color: bool = False) -> str:
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        by_file[finding.path].append(finding)
    lines: list[str] = []
    for path in sorted(by_file):
        lines.append(path)
        for finding in sorted(by_file[path], key=lambda f: (f.line, f.column)):
            severity = finding.severity.upper()
            label = typer.style(severity, fg=_COLORS[finding.severity], bold=True) if color else severity
            lines.append(f"  {finding.line}:{finding.column}  {label}  {finding.rule_id}  {finding.cwe}")
            lines.append(f"      {finding.message}")
            lines.append(f"      fix: {finding.fix}")
        lines.append("")
    for note in report.notes:
        lines.append(f"note: {note.path}:{note.line} {note.id}: {note.message}")
    for skipped in report.files_skipped:
        lines.append(f"skipped: {skipped.path} ({skipped.reason})")
    if report.truncated:
        lines.append("note: the file limit was reached; remaining files were not scanned.")
    counts = report.counts
    summary = (
        f"{len(report.findings)} finding(s): {counts.critical} critical, {counts.high} high, {counts.medium} medium, "
        f"{counts.low} low in {report.files_scanned} file(s); {report.suppressed} suppressed, "
        f"{report.baseline_filtered} in baseline, {len(report.files_skipped)} skipped; fail-on {report.fail_on}."
    )
    if not report.findings:
        lines.append("No findings.")
    return "\n".join([*lines, summary, NOTICE])
