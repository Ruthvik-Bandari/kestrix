# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix integrations`` commands. Exit codes: 0 done, 2 refused."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from . import skill

app = typer.Typer(no_args_is_help=True)


@app.callback()
def _group() -> None:
    """Connect Kestrix to other tools, such as Claude."""


def _refuse(exc: skill.SkillError) -> NoReturn:
    typer.echo(f"Refused: {exc}", err=True)
    raise typer.Exit(code=2)


DEST_OPT = typer.Option("--dest", help="Skill directory to use. Default: ~/.claude/skills/kestrix-security")


@app.command("install-claude-skill")
def install_claude_skill(
    dest: Annotated[Path | None, DEST_OPT] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace an existing copy of the skill.")] = False,
) -> None:
    """Install the kestrix-security skill for Claude Code."""
    try:
        path = skill.install(dest, force=force)
    except skill.SkillError as exc:
        _refuse(exc)
    typer.echo(f"Installed the {skill.SKILL_NAME} skill to {path}")
    typer.echo("Start a new Claude Code session to load it.")


@app.command("uninstall-claude-skill")
def uninstall_claude_skill(dest: Annotated[Path | None, DEST_OPT] = None) -> None:
    """Remove the installed kestrix-security skill."""
    try:
        path = skill.uninstall(dest)
    except skill.SkillError as exc:
        _refuse(exc)
    typer.echo(f"Removed {path}")


@app.command("package-claude-skill")
def package_claude_skill(
    out: Annotated[Path, typer.Option("--out", help="Zip file to write, e.g. kestrix-security.zip.")],
    force: Annotated[bool, typer.Option("--force", help="Replace an existing file.")] = False,
) -> None:
    """Write the skill as a zip to upload as a custom skill in Claude.ai or Claude Desktop."""
    try:
        path = skill.package(out, force=force)
    except skill.SkillError as exc:
        _refuse(exc)
    typer.echo(f"Wrote {path}")
