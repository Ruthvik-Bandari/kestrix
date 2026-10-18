# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix`` command line entry point."""

from __future__ import annotations

import getpass
import logging
import os

import typer

from . import ATTRIBUTION, __version__
from .bitcoin.cli import app as bitcoin_app
from .core import config
from .detect.cli import app as detect_app
from .forensics.cli import app as forensics_app
from .mail.cli import app as mail_app
from .webcheck.cli import app as webcheck_app

app = typer.Typer(help="Kestrix: local-first security workbench.", no_args_is_help=True, add_completion=False)
app.add_typer(detect_app, name="detect", help="Diagnose, repair and replay Sigma detections.")
app.add_typer(forensics_app, name="forensics", help="Hash, entropy and metadata analysis of files and URLs.")
app.add_typer(webcheck_app, name="webcheck", help="Passive security checks of a website you own.")
app.add_typer(bitcoin_app, name="bitcoin", help="Bitcoin address quantum-exposure scanning.")
app.add_typer(mail_app, name="mail", help="Explainable analysis of saved email messages (.eml).")
config_app = typer.Typer(help="Manage local settings and API keys.", no_args_is_help=True)
app.add_typer(config_app, name="config")


@app.command()
def version() -> None:
    """Print the installed version and author."""
    typer.echo(f"{__version__} ({ATTRIBUTION})")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", help="Interface to bind. Keep loopback unless you know why not."),
    port: int = typer.Option(8765, min=1, max=65535),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open the dashboard in a browser."),
) -> None:
    """Start the local dashboard and API."""
    import uvicorn

    from .server.app import create_app
    from .server.settings import Settings, SettingsError, load_settings

    try:
        hosted = load_settings().hosted is not None
    except SettingsError as exc:
        raise typer.BadParameter(str(exc)) from None
    if hosted:
        raise typer.BadParameter(
            "KESTRIX_MODE=hosted is for `kestrix serve-hosted`; unset it to run the local dashboard"
        )

    extra = frozenset() if host in {"127.0.0.1", "localhost", "::1"} else frozenset({host})
    url = f"http://{'localhost' if host in {'127.0.0.1', '::1'} else host}:{port}"
    typer.echo(f"{ATTRIBUTION}, version {__version__}. Dashboard at {url}  (API schema: {url}/api/openapi.json)")
    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(extra_hosts=extra, server_settings=Settings()), host=host, port=port, log_level="info")


@app.command("serve-hosted")
def serve_hosted(
    port: int | None = typer.Option(None, min=1, max=65535, help="Port to listen on. Default: $PORT, then 8000."),
) -> None:
    """Run the public hosted service with sign-in (docs/hosted.md). Configured by KESTRIX_* variables."""
    import uvicorn

    from .server.app import create_app
    from .server.settings import SettingsError, load_settings

    env_port = os.environ.get("PORT", "8000")
    if port is None and not (env_port.isdigit() and 1 <= int(env_port) <= 65535):
        raise typer.BadParameter("PORT must be a number from 1 to 65535")
    try:
        application = create_app(server_settings=load_settings(mode="hosted"))
    except SettingsError as exc:
        typer.echo(f"Hosted mode is not configured: {exc}", err=True)
        raise typer.Exit(2) from None
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    typer.echo(f"{ATTRIBUTION}, version {__version__}. Hosted mode on port {port or env_port}.")
    # TLS ends at the platform's proxy. uvicorn's own access log is off because it records query
    # strings and client addresses; kestrix.access logs a privacy-safe line instead. Proxy headers
    # stay off: client IPs for rate limits come from the socket unless KESTRIX_TRUST_PROXY_HEADERS=1.
    uvicorn.run(
        application,
        host="0.0.0.0",  # noqa: S104 - a container behind the platform's TLS proxy must listen on all interfaces
        port=port or int(env_port),
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_level="info",
    )


@config_app.command("set-anthropic-key")
def set_anthropic_key() -> None:
    """Store your Anthropic API key locally (file readable only by you)."""
    key = getpass.getpass("Anthropic API key: ").strip()
    if not key:
        raise typer.BadParameter("no key entered")
    config.set_secret("anthropic_api_key", key)
    typer.echo(f"Saved to {config.config_dir() / 'secrets.json'}")


@config_app.command("clear-anthropic-key")
def clear_anthropic_key() -> None:
    """Remove the stored Anthropic API key."""
    config.set_secret("anthropic_api_key", None)
    typer.echo("Removed.")


@config_app.command("show")
def show() -> None:
    """Show where settings live and which keys are configured (never the key itself)."""
    typer.echo(f"config dir: {config.config_dir()}")
    typer.echo(f"anthropic key configured: {config.anthropic_key() is not None}")
