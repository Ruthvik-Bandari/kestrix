# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``kestrix-scan`` commands, also run by ``kestrix code scan`` and ``kestrix integrations``.

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.

``--hook`` always exits 0: a scanner problem must never block the editor.

``kestrix-scan PATH ...`` is short for ``kestrix-scan scan PATH ...``; to scan a path named like a
subcommand, write ``kestrix-scan scan init``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from . import plugin, skill
from .about import ATTRIBUTION, __version__
from .analyze import FailOn, resolve_targets, scan, write_baseline
from .analyze import exit_code as scan_exit_code
from .config import FAIL_ON_CHOICES, Config, discover, load_file
from .errors import Rejected
from .hook import MAX_STDIN_BYTES, hook_response
from .models import NOTICE, Finding, ScanReport
from .registry import RULES
from .sarif import to_sarif

if TYPE_CHECKING:
    from .osvdb import Status

PROG = "kestrix-scan"
FORMATS = ("text", "json", "sarif")
# ANSI colors for the severity labels in text output on a terminal.
_COLORS = {"critical": "91", "high": "31", "medium": "33", "low": "36"}


def _style(text: str, code: str) -> str:
    return f"\x1b[{code}m\x1b[1m{text}\x1b[0m"


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


# ----- scan


def _scan_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Scan Python code for insecure patterns and any text file for hard-coded secrets. "
        "Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.",
    )
    parser.add_argument("paths", nargs="*", type=Path, help="Files or directories to scan. Default: '.'.")
    parser.add_argument("--format", dest="output_format", choices=FORMATS, default="text", help="text, json or sarif.")
    parser.add_argument("--output", type=Path, help="Write the report to this file instead of stdout.")
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        help="Lowest severity that makes the command exit 1; 'none' never fails. Default: [tool.kestrix] fail-on, else high.",
    )
    parser.add_argument("--baseline", type=Path, help="JSON list of fingerprints of known findings to leave out.")
    parser.add_argument(
        "--write-baseline",
        dest="new_baseline",
        type=Path,
        help="Write the current findings' fingerprints here and exit 0.",
    )
    parser.add_argument("--diff", help="Only report findings on lines changed since this git ref.")
    parser.add_argument(
        "--hook",
        action="store_true",
        help="Claude Code PostToolUse mode: read the hook JSON on stdin; always exit 0.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Read settings from this .kestrix.toml or pyproject.toml instead of searching upwards from the scan root.",
    )
    parser.add_argument("--no-config", action="store_true", help="Ignore [tool.kestrix] and .kestrix.toml.")
    return parser


def _settings(args: argparse.Namespace, paths: list[str]) -> Config:
    if args.no_config:
        return Config()
    if args.config is not None:
        settings = load_file(args.config)
    else:
        scan_root, _ = resolve_targets(paths, None)
        settings = discover(scan_root)
    for warning in settings.warnings:
        _err(f"warning: {warning}")
    return settings


def run_scan(argv: Sequence[str], prog: str = f"{PROG} scan") -> int:
    """The ``scan`` command; returns the exit code."""
    args = _scan_parser(prog).parse_args(list(argv))
    if args.hook:
        _run_hook(prog)
        return 0
    paths = [str(p) for p in args.paths or [Path(".")]]
    level: FailOn | None = args.fail_on
    try:
        settings = _settings(args, paths)
        if args.new_baseline is not None:
            report = scan(paths, config=replace(settings, baseline=None), fail_on=level, diff_base=args.diff)
            written = write_baseline(args.new_baseline, report.findings)
            _err(f"Wrote {written} fingerprint(s) to {args.new_baseline}.")
            return 0
        report = scan(paths, config=settings, fail_on=level, baseline=args.baseline, diff_base=args.diff)
    except Rejected as exc:
        _err(f"Rejected ({exc.reason.value}): {exc.detail}")
        return 2
    rendered = render(report, args.output_format, color=args.output is None and sys.stdout.isatty())
    if args.output is not None:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            _err(f"Rejected (invalid_input): cannot write {args.output}: {exc.strerror}")
            return 2
    else:
        _out(rendered)
    return scan_exit_code(report)


def _run_hook(prog: str) -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES).decode("utf-8", "replace")
        response = hook_response(raw)
    except Exception as exc:  # fail open: never block the editor on a scanner problem
        _err(f"{prog} --hook: skipped ({type(exc).__name__})")
        return
    if response is not None:
        _out(response)


def render(report: ScanReport, output_format: str, *, color: bool) -> str:
    if output_format == "json":
        return report.to_json()
    if output_format == "sarif":
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
            label = _style(severity, _COLORS[finding.severity]) if color else severity
            lines.append(f"  {finding.line}:{finding.column}  {label}  {finding.rule_id}  {finding.cwe}")
            lines.append(f"      {finding.message}")
            if finding.trace:
                lines.append("      trace: " + " → ".join(f"{step.line} {step.note}" for step in finding.trace))
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


# ----- Claude skill and plugin installers (exit codes: 0 done, 2 refused)


def _installer(prog: str, description: str, *, dest_help: str | None, out: bool) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=description)
    if dest_help is not None:
        parser.add_argument("--dest", type=Path, help=dest_help)
    if out:
        parser.add_argument("--out", type=Path, required=True, help="Zip file to write.")
    parser.add_argument("--force", action="store_true", help="Replace an existing copy or file.")
    return parser


SKILL_DEST = "Skill directory to use. Default: ~/.claude/skills/kestrix-security"
PLUGIN_DEST = "Plugin directory to use. Default: ~/.claude/kestrix-plugin"


def _refused(exc: Exception) -> int:
    _err(f"Refused: {exc}")
    return 2


def install_claude_skill(argv: Sequence[str], prog: str) -> int:
    args = _installer(prog, "Install the kestrix-security skill for Claude Code.", dest_help=SKILL_DEST, out=False)
    ns = args.parse_args(list(argv))
    try:
        path = skill.install(ns.dest, force=ns.force)
    except skill.SkillError as exc:
        return _refused(exc)
    _out(f"Installed the {skill.SKILL_NAME} skill to {path}")
    _out("Start a new Claude Code session to load it.")
    return 0


def uninstall_claude_skill(argv: Sequence[str], prog: str) -> int:
    parser = argparse.ArgumentParser(prog=prog, description="Remove the installed kestrix-security skill.")
    parser.add_argument("--dest", type=Path, help=SKILL_DEST)
    ns = parser.parse_args(list(argv))
    try:
        path = skill.uninstall(ns.dest)
    except skill.SkillError as exc:
        return _refused(exc)
    _out(f"Removed {path}")
    return 0


def package_claude_skill(argv: Sequence[str], prog: str) -> int:
    description = "Write the skill as a zip to upload as a custom skill in Claude.ai or Claude Desktop."
    ns = _installer(prog, description, dest_help=None, out=True).parse_args(list(argv))
    try:
        path = skill.package(ns.out, force=ns.force)
    except skill.SkillError as exc:
        return _refused(exc)
    _out(f"Wrote {path}")
    return 0


def plugin_instructions(path: Path) -> list[str]:
    """How to enable an installed copy of the plugin; nothing in Claude Code's settings is changed."""
    quoted = shlex.quote(str(path))
    return [
        "Nothing was changed in your Claude Code settings. To enable it, run in your shell:",
        f"  claude plugin marketplace add {quoted}",
        f"  claude plugin install {plugin.PLUGIN_NAME}@{plugin.LOCAL_MARKETPLACE}",
        "or in a Claude Code session:",
        f"  /plugin marketplace add {path}",
        f"  /plugin install {plugin.PLUGIN_NAME}@{plugin.LOCAL_MARKETPLACE}",
        f"To try it for one session only: claude --plugin-dir {quoted}",
    ]


def install_claude_plugin(argv: Sequence[str], prog: str) -> int:
    description = "Copy the kestrix Claude Code plugin to a local directory and print how to enable it."
    ns = _installer(prog, description, dest_help=PLUGIN_DEST, out=False).parse_args(list(argv))
    try:
        path = plugin.install(ns.dest, force=ns.force)
    except skill.SkillError as exc:
        return _refused(exc)
    _out(f"Installed the {plugin.PLUGIN_NAME} plugin to {path}")
    for line in plugin_instructions(path):
        _out(line)
    return 0


def package_claude_plugin(argv: Sequence[str], prog: str) -> int:
    description = "Write the plugin as a deterministic zip, loadable with claude --plugin-dir FILE.zip."
    ns = _installer(prog, description, dest_help=None, out=True).parse_args(list(argv))
    try:
        path = plugin.package(ns.out, force=ns.force)
    except skill.SkillError as exc:
        return _refused(exc)
    _out(f"Wrote {path}")
    return 0


# ----- db: the local OSV vulnerability index


def run_db(argv: Sequence[str], prog: str) -> int:
    from . import osvdb

    parser = argparse.ArgumentParser(
        prog=prog,
        description="Manage the local OSV vulnerability index used to check lockfiles. `update` is the only "
        "kestrix-scan command that uses the network: it downloads the OSV export of each ecosystem over HTTPS.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    update = actions.add_parser("update", help="Download the OSV data and rebuild the index (uses the network).")
    update.add_argument(
        "--ecosystem",
        nargs="+",
        choices=osvdb.ECOSYSTEMS,
        default=list(osvdb.ECOSYSTEMS),
        help="Ecosystems to download. Default: all of them.",
    )
    actions.add_parser("status", help="Show where the index is, how old it is and what it holds.")
    ns = parser.parse_args(list(argv))
    if ns.action == "update":
        started = time.monotonic()
        tty = sys.stderr.isatty()

        def progress(line: str) -> None:
            sys.stderr.write(f"\r\x1b[K{line}" if tty else line + "\n")
            sys.stderr.flush()

        try:
            path = osvdb.update(ns.ecosystem, progress=progress)
        except Rejected as exc:
            if tty:
                _err("")
            _err(f"Rejected ({exc.reason.value}): {exc.detail}")
            return 2
        if tty:
            _err("")
        _out(f"Updated {path} in {time.monotonic() - started:.1f} s.")
    return _db_status(osvdb.status())


def _db_status(state: Status) -> int:
    from .osvdb import STALE_AFTER_S

    if not state.sources:
        _out(f"No vulnerability index at {state.path}. Run `kestrix-scan db update` (downloads the OSV data).")
        return 1
    age = state.age_s() or 0.0
    stale = " (stale: run `kestrix-scan db update`)" if age > STALE_AFTER_S else ""
    _out(f"Index: {state.path} (built {state.built_at})")
    _out(f"Age: {age / 86400:.1f} days{stale}")
    for source in state.sources:
        advisories, malicious = state.counts.get(source.ecosystem, (0, 0))
        _out(
            f"  {source.ecosystem}: {advisories:,} advisories ({malicious:,} malicious-package reports); "
            f"downloaded {source.downloaded_at}, {source.size / 1e6:.1f} MB, sha256 {source.sha256}"
        )
    return 0


# ----- init, rules, version


def run_init(argv: Sequence[str], prog: str) -> int:
    from . import init

    parser = argparse.ArgumentParser(
        prog=prog,
        description="Set up kestrix-scan in this project: [tool.kestrix] in pyproject.toml, and optionally "
        "pre-commit, a GitHub Actions workflow that uploads SARIF, and the Claude Code plugin. Safe to re-run.",
    )
    parser.add_argument("--ci", choices=("github",), help="Write .github/workflows/kestrix.yml.")
    parser.add_argument("--pre-commit", action="store_true", help="Add the kestrix-scan hook to pre-commit.")
    parser.add_argument("--claude-plugin", action="store_true", help="Install the Claude Code plugin.")
    parser.add_argument("--force", action="store_true", help="Replace an existing [tool.kestrix] table or files.")
    parser.add_argument("--dir", type=Path, default=Path("."), help="Project directory. Default: '.'.")
    ns = parser.parse_args(list(argv))
    try:
        steps = init.init(ns.dir, ci=ns.ci, pre_commit=ns.pre_commit, claude_plugin=ns.claude_plugin, force=ns.force)
    except (init.InitError, skill.SkillError) as exc:
        return _refused(exc)
    for step in steps:
        _out(step)
    return 0


def list_rules(argv: Sequence[str], prog: str) -> int:
    parser = argparse.ArgumentParser(prog=prog, description="List the rule ids, severities and CWEs.")
    parser.parse_args(list(argv))
    width = max(len(rule_id) for rule_id in RULES)
    for rule in RULES.values():
        _out(f"{rule.id:<{width}}  {rule.severity:<8}  {rule.cwe:<8}  {rule.title}")
    return 0


def show_version(argv: Sequence[str], prog: str) -> int:
    argparse.ArgumentParser(prog=prog, description="Print the installed version and author.").parse_args(list(argv))
    _out(f"{__version__} ({ATTRIBUTION})")
    return 0


Command = Callable[[Sequence[str], str], int]
COMMANDS: dict[str, tuple[Command, str]] = {
    "scan": (run_scan, "Scan files (the default command)."),
    "init": (run_init, "Add [tool.kestrix], pre-commit, a GitHub workflow or the Claude plugin to a project."),
    "rules": (list_rules, "List the rules."),
    "db": (run_db, "Update (network) or show the local OSV vulnerability index for lockfile checks."),
    "install-claude-plugin": (install_claude_plugin, "Install the Claude Code plugin to a local directory."),
    "package-claude-plugin": (package_claude_plugin, "Write the Claude Code plugin as a zip."),
    "install-claude-skill": (install_claude_skill, "Install the kestrix-security skill for Claude Code."),
    "uninstall-claude-skill": (uninstall_claude_skill, "Remove the installed kestrix-security skill."),
    "package-claude-skill": (package_claude_skill, "Write the kestrix-security skill as a zip."),
    "version": (show_version, "Print the version."),
}


def _usage(prog: str) -> str:
    width = max(len(name) for name in COMMANDS)
    rows = [f"  {name:<{width}}  {text}" for name, (_, text) in COMMANDS.items()]
    return "\n".join(
        [
            f"usage: {prog} [scan] [PATH ...] [--format text|json|sarif] [--output FILE] [--fail-on LEVEL]",
            f"       {prog} COMMAND [--help]",
            "",
            "Local security checks for Python code, hard-coded secrets and dependency lockfiles. Nothing leaves the",
            "machine; only `db update` uses the network, to download the OSV vulnerability data.",
            "",
            "commands:",
            *rows,
            "",
            f"Run `{prog} scan --help` for the scan options. {ATTRIBUTION}, version {__version__}.",
        ]
    )


def main(argv: Sequence[str] | None = None, prog: str = PROG) -> int:
    """Run one command and return its exit code. ``prog`` is the name shown in help and messages."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["--version"], ["-V"]):
        _out(f"{__version__} ({ATTRIBUTION})")
        return 0
    if args[:1] in (["--help"], ["-h"]):
        _out(_usage(prog))
        return 0
    name = args.pop(0) if args and args[0] in COMMANDS else "scan"
    command, _ = COMMANDS[name]
    try:
        return command(args, f"{prog} {name}")
    except SystemExit as exc:  # argparse exits 0 after --help and 2 on a usage error
        return exc.code if isinstance(exc.code, int) else 2
