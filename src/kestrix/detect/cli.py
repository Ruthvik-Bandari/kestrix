# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix detect`` commands.

Exit codes: 0 repaired or unchanged; 2 invalid input; 3 engine unavailable;
10 abstained or insufficient evidence; 11 unsupported rule.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import typer

from ..core.errors import Rejected
from ..core.evidence import write_artifact
from . import cases
from .api import engine_url
from .engine import PINNED_IMAGE, Elasticsearch
from .workflow import Inputs, Outcome, run

app = typer.Typer(no_args_is_help=True)

EXIT = {
    Outcome.REPAIRED: 0,
    Outcome.UNCHANGED: 0,
    Outcome.ENGINE_UNAVAILABLE: 3,
    Outcome.ABSTAINED: 10,
    Outcome.INSUFFICIENT_EVIDENCE: 10,
    Outcome.UNSUPPORTED: 11,
}


def _summary(report: dict[str, Any]) -> str:
    lines = [f"outcome: {report['outcome']}"]
    if report.get("reason"):
        lines.append(f"reason:  {report['reason']}")
    if "rule" in report:
        lines.append(f"rule:    {report['rule']['title']}  ({report['rule']['sha256'][:12]})")
    for hyp in report.get("hypotheses", []):
        detail = ", ".join(hyp["fields"] or hyp["evidence_event_ids"][:3])
        lines.append(f"finding: {hyp['family']} [{', '.join(hyp['reason_codes'])}] {detail}")
    for rec in report.get("telemetry_recommendations", []):
        lines.append(f"collect: {rec['field']}: {rec['guidance']}")
    original = report.get("original", {})
    for split, res in original.items():
        c = res["counts"]
        lines.append(f"original {split}: TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']}")
    for cand in report.get("candidates", []):
        status = "passed" if cand.get("passed") else ", ".join(cand.get("policy_failures", ["screened"]))
        lines.append(f"candidate {cand['candidate']['proposal_id']}: {status}")
    if report.get("diff"):
        lines += ["", report["diff"]]
    if report.get("provisional"):
        lines.append("note: provisional — supply validation fixtures before approving")
    return "\n".join(lines)


def _emit(report: dict[str, Any], as_json: bool, evidence_dir: Path | None) -> None:
    if evidence_dir is not None:
        digest, path = write_artifact(evidence_dir, report)
        report = {**report, "evidence": {"sha256": digest, "path": str(path)}}
    typer.echo(json.dumps(report, indent=2) if as_json else _summary(report))
    if evidence_dir is not None and not as_json:
        typer.echo(f"evidence: {report['evidence']['path']}")
    raise typer.Exit(EXIT[Outcome(report["outcome"])])


def _execute(inputs: Inputs, as_json: bool, evidence_dir: Path | None) -> None:
    es = Elasticsearch(engine_url())
    try:
        report = run(inputs, es)
    except Rejected as exc:
        typer.echo(f"error: {exc.reason}: {exc.detail}", err=True)
        raise typer.Exit(2) from None
    finally:
        es.close()
    _emit(report, as_json, evidence_dir)


JSON_OPT = typer.Option(False, "--json", help="Print the full machine-readable report.")
EVIDENCE_OPT = typer.Option(None, "--evidence-dir", help="Also write the report as a content-addressed artifact here.")


@app.command("cases")
def list_cases() -> None:
    """List the bundled demonstration cases."""
    for c in cases.list_cases():
        typer.echo(f"{c['case_id']:38} expected={c['expected']['outcome']:22} {c['title']}")


@app.command()
def demo(case_id: str, as_json: bool = JSON_OPT, evidence_dir: Path | None = EVIDENCE_OPT) -> None:
    """Run a bundled case end to end (requires the pinned engine; see `engine-up`)."""
    try:
        inputs = cases.inputs(case_id)
    except Rejected as exc:
        typer.echo(f"error: {exc.detail}", err=True)
        raise typer.Exit(2) from None
    _execute(inputs, as_json, evidence_dir)


@app.command("run")
def run_cmd(
    rule: Path = typer.Option(..., exists=True, dir_okay=False, help="Sigma rule YAML"),
    mapping: Path = typer.Option(..., exists=True, dir_okay=False, help="Environment field mapping YAML"),
    dev: Path = typer.Option(..., exists=True, dir_okay=False, help="Labeled development fixtures (JSONL)"),
    validation: Path | None = typer.Option(
        None, exists=True, dir_okay=False, help="Held-out validation fixtures (JSONL)"
    ),
    healthy_rule: Path | None = typer.Option(None, exists=True, dir_okay=False),
    healthy_mapping: Path | None = typer.Option(None, exists=True, dir_okay=False),
    as_json: bool = JSON_OPT,
    evidence_dir: Path | None = EVIDENCE_OPT,
) -> None:
    """Diagnose, repair and validate your own rule and fixtures."""
    inputs = Inputs(
        rule.read_text(),
        mapping.read_text(),
        dev,
        validation,
        healthy_rule.read_text() if healthy_rule else None,
        healthy_mapping.read_text() if healthy_mapping else None,
    )
    _execute(inputs, as_json, evidence_dir)


@app.command("engine-status")
def engine_status() -> None:
    """Show whether the pinned Elasticsearch is reachable."""
    es = Elasticsearch(engine_url(), timeout=3)
    try:
        es.require_pinned()
    except Rejected as exc:
        typer.echo(f"not ready: {exc.detail} ({engine_url()})")
        raise typer.Exit(3) from None
    finally:
        es.close()
    typer.echo(f"ready: {engine_url()}")


@app.command("engine-up")
def engine_up(name: str = typer.Option("kestrix-es", help="Container name")) -> None:
    """Start the pinned single-node Elasticsearch in Docker, bound to 127.0.0.1:9200."""
    docker = shutil.which("docker")
    if docker is None:
        typer.echo("Docker is required: https://docs.docker.com/get-docker/", err=True)
        raise typer.Exit(3)
    argv = [
        docker,
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1:9200:9200",
        "-e",
        "discovery.type=single-node",
        "-e",
        "xpack.security.enabled=false",
        "-e",
        "ES_JAVA_OPTS=-Xms1g -Xmx1g",
        PINNED_IMAGE,
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603 - fixed argv
    if result.returncode != 0:
        typer.echo(result.stderr.strip() or "docker run failed", err=True)
        raise typer.Exit(3)
    typer.echo(f"started {name}; wait ~30 s, then run `kestrix detect engine-status`")
