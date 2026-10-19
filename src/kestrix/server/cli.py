# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix hosted`` operator commands for the hosted service (docs/hosted.md, "Abuse handling").

They read the same ``KESTRIX_*`` settings as ``kestrix serve-hosted``, so run them where the
service runs (for example ``fly ssh console -C "kestrix hosted ..."``). They never print secrets.
Exit codes: 0 done, 1 no matching account, 2 hosted mode not configured.
"""

from __future__ import annotations

import time

import typer

from .auth import host_tag
from .settings import HostedSettings, SettingsError, load_settings
from .store import Store

app = typer.Typer(no_args_is_help=True)


@app.callback()
def _group() -> None:
    """Operator commands for the hosted service."""


def _settings() -> HostedSettings:
    try:
        hosted = load_settings(mode="hosted").hosted
    except SettingsError as exc:
        typer.echo(f"Hosted mode is not configured: {exc}", err=True)
        raise typer.Exit(2) from None
    assert hosted is not None
    return hosted


def _store() -> Store:
    path = _settings().db_path
    if not path.is_file():
        typer.echo(f"No hosted database at {path}.", err=True)
        raise typer.Exit(2)
    try:
        return Store(path)
    except SettingsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from None


def _set_disabled(email: str, disabled_at: int | None) -> int:
    store = _store()
    try:
        return store.set_disabled(email, disabled_at)
    finally:
        store.close()


@app.command("disable-user")
def disable_user(email: str = typer.Option(..., "--email", help="Email of the account(s) to disable.")) -> None:
    """Block every account with this email from signing in and end its sessions."""
    count = _set_disabled(email, int(time.time()))
    if not count:
        typer.echo("No account has that email.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Disabled {count} account(s); their sessions have ended.")


@app.command("enable-user")
def enable_user(email: str = typer.Option(..., "--email", help="Email of the account(s) to re-enable.")) -> None:
    """Allow every account with this email to sign in again."""
    count = _set_disabled(email, None)
    if not count:
        typer.echo("No account has that email.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Enabled {count} account(s).")


@app.command("hash-host")
def hash_host(host: str = typer.Argument(..., help="A host name or URL from an abuse report.")) -> None:
    """Print the host tag that `kestrix.webcheck` log lines carry for this host."""
    tag = host_tag(_settings().log_salt, host)
    if tag == "-":
        raise typer.BadParameter("give a host name such as site.example or a URL")
    typer.echo(tag)
