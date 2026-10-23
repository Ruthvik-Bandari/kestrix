# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run one scanner over one shard directory and reduce its report to finding records.

A shard directory holds ``b/``, ``a/`` and ``u/`` (before, after and unchanged files named ``<id>.<ext>``), so a
report path tells the file kind and id. Each tool runs with the shard as its working directory, with its own defaults:

* **kestrix**: ``python -m kestrix_scan scan . --no-config --fail-on none --format json`` from the checked-out code;
* **bandit**: ``bandit -r . -f json --exit-zero`` (every test, every severity and confidence), the pin of ``bench/``;
* **eslint**: ESLint with ``eslint-plugin-security`` (all its rules at the plugin's ``recommended`` setting), parsing
  JavaScript and TypeScript with typescript-eslint's parser. It runs on Node from the cluster module, offline.

Semgrep is not run (its registry rules are not licensed for this use and no OSS-licensed local ruleset was available).
The reduced records hold file kind and id, rule id, line range and families; raw reports are not kept.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .common import EXTENSIONS, KINDS, LOCK_NAME, WEB_EXTENSIONS, CodeBenchError, Layout, now, write_json, write_jsonl
from .families import bandit_families, eslint_families, kestrix_families

TOOLS = ("kestrix", "bandit", "eslint")
TUNING = "tuning"  # round-1 dev plus the round-1 test, which is spent (LOCKED_EVAL.json) and so usable for tuning
TUNING_PARTS = ("dev", "test")


def base_tool(name: str) -> str:
    """``kestrix@r1`` is the kestrix scanner of another code tree; the tool is the part before ``@``."""
    return name.partition("@")[0]


TOOL_TIMEOUT_S = 3 * 3600
ESLINT_CONFIG = """\
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

const files = ["**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}"];
export default [
  {
    files,
    languageOptions: { parser: tseslint.parser, parserOptions: { ecmaFeatures: { jsx: true } } },
    linterOptions: { reportUnusedDisableDirectives: "off" },
  },
  { files: ["**/*.{ts,mts,cts}"], languageOptions: { parser: tseslint.parser, parserOptions: { ecmaFeatures: { jsx: false } } } },
  { ...security.configs.recommended, files },
];
"""
_NOT_PARSED = re.compile(r"syntax|parsing|parse|tokeniz", re.IGNORECASE)

Record = dict[str, Any]


def locate(path: str) -> tuple[str, str] | None:
    """(kind, file id) from a path such as ``b/0123abcd.py``, or None if it is not one of ours."""
    parts = PurePosixPath(path.removeprefix("./")).parts
    if len(parts) != 2 or parts[0] not in KINDS:
        return None
    return parts[0], PurePosixPath(parts[1]).stem


def record(path: str, rule: str, line: int, end_line: int, families: frozenset[str]) -> Record | None:
    located = locate(path)
    if located is None:
        return None
    kind, file_id = located
    return {"k": kind, "i": file_id, "r": rule, "l": line, "e": max(line, end_line), "f": sorted(families)}


def reduce_kestrix(report: dict[str, Any]) -> tuple[list[Record], dict[str, int]]:
    out = []
    for item in report["findings"]:
        rec = record(
            item["path"],
            item["rule_id"],
            item["line"],
            item["end_line"],
            kestrix_families(item["rule_id"], item.get("cwe") or ""),
        )
        if rec:
            out.append(rec)
    failed: dict[str, int] = {}
    for item in report.get("files_skipped", []):
        located = locate(item["path"])
        if located:
            failed[located[0]] = failed.get(located[0], 0) + 1
    return out, failed


def reduce_bandit(report: dict[str, Any]) -> tuple[list[Record], dict[str, int]]:
    out = []
    for item in report["results"]:
        cwe = (item.get("issue_cwe") or {}).get("id")
        lines = item.get("line_range") or [item["line_number"]]
        rec = record(
            item["filename"],
            item["test_id"],
            min(lines),
            max(lines),
            bandit_families(item["test_id"], int(cwe) if cwe else None),
        )
        if rec:
            out.append(rec)
    failed: dict[str, int] = {}
    for item in report.get("errors", []):
        located = locate(item["filename"])
        if located:
            failed[located[0]] = failed.get(located[0], 0) + 1
    return out, failed


def reduce_eslint(report: list[dict[str, Any]], cwd: Path) -> tuple[list[Record], dict[str, int]]:
    out = []
    failed: dict[str, int] = {}
    base = cwd.resolve()
    for item in report:
        rel = Path(item["filePath"]).resolve().relative_to(base).as_posix()
        for msg in item.get("messages", []):
            rule = msg.get("ruleId")
            if rule is not None and not rule.startswith("security/"):
                continue  # a disable comment naming a rule that is not loaded makes eslint report that rule id
            if rule is None:
                if msg.get("fatal") or _NOT_PARSED.search(msg.get("message", "")):
                    located = locate(rel)
                    if located:
                        failed[located[0]] = failed.get(located[0], 0) + 1
                continue
            rec = record(rel, rule, msg.get("line", 1), msg.get("endLine") or msg.get("line", 1), eslint_families(rule))
            if rec:
                out.append(rec)
    return out, failed


def _run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> float:
    start = time.perf_counter()
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        args, cwd=cwd, capture_output=True, text=True, timeout=TOOL_TIMEOUT_S, check=False, env=env
    )
    seconds = time.perf_counter() - start
    if proc.returncode not in (0, 1):
        raise CodeBenchError(f"{Path(args[0]).name} exited {proc.returncode}: {proc.stderr.strip()[-1500:]}")
    return seconds


def _version(args: list[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, check=True)  # noqa: S603
    return proc.stdout.strip().splitlines()[0]


def count_files(directory: Path, tool: str) -> dict[str, int]:
    """Files per kind that the tool can read: every source and web file for kestrix, ``.py`` for bandit, JavaScript and TypeScript for eslint."""
    wanted = {
        "kestrix": tuple(EXTENSIONS),
        "bandit": (".py",),
        "eslint": tuple(e for e in EXTENSIONS if e != ".py" and e not in WEB_EXTENSIONS),
    }[base_tool(tool)]
    return {kind: sum(1 for p in (directory / kind).glob("*") if p.suffix in wanted) for kind in KINDS}


def run_tool(
    layout: Layout, tool: str, shard_dir: Path, scratch: Path, tree: Path | None = None
) -> tuple[str, float, list[Record], dict[str, int]]:
    """(version, seconds, findings, files the tool could not parse by kind). ``tree``: run kestrix from that code tree."""
    report = scratch / f"{tool}.json"
    tool = base_tool(tool)
    if tool == "kestrix":
        from kestrix_scan import __version__

        args = [sys.executable, "-m", "kestrix_scan", "scan", ".", "--no-config", "--fail-on", "none"]
        env = None if tree is None else {**os.environ, "PYTHONPATH": str(tree / "packages" / "kestrix-scan" / "src")}
        seconds = _run([*args, "--format", "json", "--output", str(report)], shard_dir, env)
        found, failed = reduce_kestrix(json.loads(report.read_text(encoding="utf-8")))
        return __version__, seconds, found, failed
    if tool == "bandit":
        exe = layout.tools / "venv-bandit" / "bin" / "bandit"
        seconds = _run([str(exe), "-r", ".", "-f", "json", "-o", str(report), "-q", "--exit-zero"], shard_dir)
        found, failed = reduce_bandit(json.loads(report.read_text(encoding="utf-8")))
        return _version([str(exe), "--version"]).split()[1], seconds, found, failed
    if tool == "eslint":
        home = layout.tools / "eslint"
        config = home / "eslint.config.mjs"
        config.write_text(ESLINT_CONFIG, encoding="utf-8")
        cli = home / "node_modules" / "eslint" / "bin" / "eslint.js"
        args = [
            "node",
            str(cli),
            "-c",
            str(config),
            "--format",
            "json",
            "--output-file",
            str(report),
            "--no-warn-ignored",
            "--no-error-on-unmatched-pattern",
            ".",
        ]
        seconds = _run(args, shard_dir)
        found, failed = reduce_eslint(json.loads(report.read_text(encoding="utf-8")), shard_dir)
        plugin = json.loads((home / "node_modules" / "eslint-plugin-security" / "package.json").read_text())["version"]
        return (
            f"eslint {_version(['node', str(cli), '--version'])} + eslint-plugin-security {plugin}",
            seconds,
            found,
            failed,
        )
    raise CodeBenchError(f"unknown tool {tool!r}; choose from {', '.join(TOOLS)}")


def scan_shard(
    layout: Layout,
    tool: str,
    split: str,
    shard: int,
    *,
    run: str,
    code_sha: str,
    locked: bool = False,
    tree: Path | None = None,
) -> Path:
    """Scan one shard with one tool and write ``findings.jsonl`` and ``report.json``.

    The test split needs ``locked``. Split ``tuning`` scans the dev and the test shard together and needs the claimed
    ``LOCKED_EVAL.json`` of the round-1 test, which is spent. ``tool`` may be ``kestrix@LABEL`` with ``tree`` the code
    tree whose scanner runs.
    """
    if split == "test" and not locked:
        raise CodeBenchError("the test split is read only by the locked test (see `locked-test`)")
    if split == TUNING and not (layout.reports / LOCK_NAME).is_file():
        raise CodeBenchError("the test split is not spent (no LOCKED_EVAL.json); it cannot be used for tuning")
    parts = TUNING_PARTS if split == TUNING else (split,)
    scratch = layout.scan_dir(run, tool) / f".scratch-{split}-{shard:02d}"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    files: dict[str, int] = dict.fromkeys(KINDS, 0)
    unparsed: dict[str, int] = {}
    found: list[Record] = []
    seconds, version = 0.0, ""
    for part in parts:
        shard_dir = layout.shard_dir(part, shard)
        if not shard_dir.is_dir():
            raise CodeBenchError(f"{shard_dir} is missing; run build first")
        for kind, count in count_files(shard_dir, tool).items():
            files[kind] += count
        version, took, records, failed = run_tool(layout, tool, shard_dir, scratch, tree)
        seconds += took
        found += records
        for kind, count in failed.items():
            unparsed[kind] = unparsed.get(kind, 0) + count
    for leftover in scratch.iterdir():
        leftover.unlink()
    scratch.rmdir()
    write_jsonl(layout.findings_file(run, tool, shard), found)
    write_json(
        layout.scan_report(run, tool, shard),
        {
            "schema_version": 1,
            "tool": tool,
            "tool_version": version,
            "run": run,
            "code_sha": code_sha,
            "split": split,
            "shard": shard,
            "finished_at": now(),
            "seconds": round(seconds, 2),
            "files": files,
            "unparsed": unparsed,
            "findings": len(found),
        },
    )
    return layout.findings_file(run, tool, shard)
