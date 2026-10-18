# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""``kestrix bitcoin`` commands.

Exit codes: 0 success, 2 rejected input, 3 upstream service or AI key unavailable.
"""

from __future__ import annotations

from typing import Annotated, NoReturn

import typer

from ..core.errors import Reason, Rejected
from . import guardian
from .chain import MempoolClient
from .migration import parse_address_type, plan_for
from .models import AddressAssessment, PublicTestnet
from .risk import scan as scan_inputs

app = typer.Typer(no_args_is_help=True)

EXIT_REJECTED = 2
EXIT_UNAVAILABLE = 3
_UNAVAILABLE = frozenset(
    {Reason.UPSTREAM_ERROR, Reason.AI_KEY_MISSING, Reason.TARGET_UNREACHABLE, Reason.TARGET_NOT_ALLOWED}
)


def _fail(exc: Rejected) -> NoReturn:
    typer.echo(f"error ({exc.reason.value}): {exc.detail}", err=True)
    raise typer.Exit(EXIT_UNAVAILABLE if exc.reason in _UNAVAILABLE else EXIT_REJECTED)


def _print_assessment(item: AddressAssessment) -> None:
    network = item.network.value if item.network else "no network"
    typer.echo(f"[{item.risk.value.upper()}] {item.input}  ({item.address_type.value}, {network})")
    typer.echo(f"  {item.explanation}")
    typer.echo(f"  What to do: {item.recommendation}")


@app.command()
def scan(
    addresses: Annotated[list[str], typer.Argument(help="Addresses or hex public keys (up to 100).")],
    lookup_chain: Annotated[
        bool, typer.Option("--lookup-chain", help="Check spend history on mempool.space (sends the addresses there).")
    ] = False,
    testnet: Annotated[
        PublicTestnet, typer.Option(help="Public test chain for tb1/m/n/2 addresses.")
    ] = PublicTestnet.TESTNET4,
    as_json: Annotated[bool, typer.Option("--json", help="Print the result as JSON.")] = False,
) -> None:
    """Check addresses for public-key exposure to future quantum attacks."""
    try:
        if lookup_chain:
            with MempoolClient(testnet=testnet) as client:
                result = scan_inputs(addresses, lookup=client.activity)
        else:
            result = scan_inputs(addresses)
    except Rejected as exc:
        _fail(exc)
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
        return
    for item in result.results:
        _print_assessment(item)
    counts = ", ".join(f"{risk.value} {count}" for risk, count in result.summary.by_risk.items())
    typer.echo(f"\n{result.summary.total} scanned: {counts}")


@app.command()
def migration(
    address_type: Annotated[str, typer.Argument(help="P2PK, P2PKH, P2SH, P2WPKH, P2WSH or P2TR.")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the plan as JSON.")] = False,
) -> None:
    """Show step-by-step migration advice for an address type."""
    try:
        plan = plan_for(parse_address_type(address_type))
    except Rejected as exc:
        _fail(exc)
    if as_json:
        typer.echo(plan.model_dump_json(indent=2))
        return
    typer.echo(f"{plan.address_type.value} (urgency: {plan.urgency})\n{plan.summary}\n")
    for number, step in enumerate(plan.steps, start=1):
        typer.echo(f"{number}. {step}")
    typer.echo("\nCautions:")
    for caution in plan.cautions:
        typer.echo(f"- {caution}")


@app.command()
def ask(
    message: Annotated[str, typer.Argument(help="A question or request in plain language.")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the result as JSON.")] = False,
) -> None:
    """Classify a plain-language request with your own Anthropic API key. Nothing is executed."""
    try:
        result = guardian.classify_intent(message, guardian.build_client())
    except Rejected as exc:
        _fail(exc)
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
        return
    typer.echo(f"Intent: {result.intent.value}")
    if result.addresses:
        typer.echo(f"Addresses: {' '.join(result.addresses)}")
    if result.ignored_addresses:
        typer.echo(f"Ignored (not valid or not in your message): {' '.join(result.ignored_addresses)}")
    typer.echo(f"Understood as (model-written): {result.model_summary}")
    typer.echo(f"Next step: {result.next_step}")
