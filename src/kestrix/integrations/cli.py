# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix integrations`` commands. Exit codes: 0 done, 2 refused.

Each command runs the ``kestrix-scan`` command of the same name (``kestrix_scan.cli``), which owns
the Claude Code plugin and the ``kestrix-security`` skill since ADR 0006.
"""

from __future__ import annotations

import typer

from kestrix_scan.cli import main as scan_main

app = typer.Typer(no_args_is_help=True)
PASS_THROUGH = {"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []}
COMMANDS = {
    "install-claude-skill": "Install the kestrix-security skill for Claude Code.",
    "uninstall-claude-skill": "Remove the installed kestrix-security skill.",
    "package-claude-skill": "Write the skill as a zip to upload as a custom skill in Claude.ai or Claude Desktop.",
    "install-claude-plugin": "Copy the kestrix Claude Code plugin to a local directory and print how to enable it.",
    "package-claude-plugin": "Write the plugin as a deterministic zip, loadable with claude --plugin-dir FILE.zip.",
}


@app.callback()
def _group() -> None:
    """Connect Kestrix to other tools, such as Claude."""


def _delegate(name: str, help_text: str) -> None:
    def command(ctx: typer.Context) -> None:
        raise typer.Exit(code=scan_main([name, *ctx.args], prog="kestrix integrations"))

    command.__doc__ = help_text
    app.command(name, context_settings=PASS_THROUGH, add_help_option=False)(command)


for _name, _help in COMMANDS.items():
    _delegate(_name, _help)
