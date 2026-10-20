# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix code`` commands: ``kestrix code scan ...`` runs ``kestrix-scan scan ...`` with the same arguments.

Options, output and exit codes are those of ``kestrix_scan.cli`` (0 no findings at or above
--fail-on, 1 findings, 2 usage or input error; ``--hook`` always exits 0).
"""

from __future__ import annotations

import typer

from kestrix_scan.cli import main as scan_main

app = typer.Typer(no_args_is_help=True)
PASS_THROUGH = {"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []}


@app.callback()
def _group() -> None:
    """Find security issues in source code (exits non-zero on findings)."""


@app.command("scan", context_settings=PASS_THROUGH, add_help_option=False)
def scan_command(ctx: typer.Context) -> None:
    """Scan Python code for insecure patterns and any text file for hard-coded secrets (see --help)."""
    raise typer.Exit(code=scan_main(["scan", *ctx.args], prog="kestrix code"))
