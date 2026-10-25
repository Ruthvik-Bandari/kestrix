# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run one scanner over one shard directory and reduce its report to finding records.

A shard directory holds ``b/``, ``a/`` and ``u/`` (before, after and unchanged files named ``<id>.<ext>``), so a
report path tells the file kind and id. Each tool runs with the shard as its working directory, with its own defaults:

* **kestrix**: ``python -m kestrix_scan scan . --no-config --fail-on none --format json`` from the checked-out code;
* **bandit**: ``bandit -r . -f json --exit-zero`` (every test, every severity and confidence), the pin of ``kestrixscanbench``;
* **flawfinder** (GPL-2.0, run as an external program, never vendored): ``flawfinder --csv .`` at its default level
  on the C and C++ files; **opengrep-sys**: Opengrep with the ``c``, ``rust`` and ``swift`` folders of opengrep-rules;
* **eslint**: ESLint with ``eslint-plugin-security`` (all its rules at the plugin's ``recommended`` setting), parsing
  JavaScript and TypeScript with typescript-eslint's parser. It runs on Node from the cluster module, offline.

Semgrep is not run (its registry rules are not licensed for this use and no OSS-licensed local ruleset was available).
The reduced records hold file kind and id, rule id, line range and families; raw reports are not kept.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    C_EXTENSIONS,
    EXTENSIONS,
    KINDS,
    LOCK_NAME,
    P5_EXTENSIONS,
    PHP_EXTENSIONS,
    WEB_EXTENSIONS,
    CodeBenchError,
    Layout,
    now,
    write_json,
    write_jsonl,
)
from .families import bandit_families, eslint_families, families_for_cwes, kestrix_families, parse_cwes, psalm_families

TOOLS = ("kestrix", "bandit", "eslint")
SCAN_TOOLS = (*TOOLS, "psalm", "flawfinder", "opengrep-sys")  # psalm: the PHP root; the other two: the Phase 5 root
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


def reduce_psalm(issues: list[dict[str, Any]], rel: str) -> tuple[list[Record], int]:
    """Taint findings of one file (``rel`` is its path in the shard) and 1 when Psalm could not parse it."""
    out = []
    for item in issues:
        kind = item.get("type", "")
        if kind == "ParseError":
            return [], 1
        if kind.startswith("Tainted"):
            line = int(item.get("line_from") or 1)
            rec = record(rel, kind, line, int(item.get("line_to") or line), psalm_families(kind))
            if rec:
                out.append(rec)
    return out, 0


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
        "psalm": PHP_EXTENSIONS,
        "flawfinder": C_EXTENSIONS,
        "opengrep-sys": P5_EXTENSIONS,
        "eslint": tuple(
            e for e in EXTENSIONS if e != ".py" and e not in (*WEB_EXTENSIONS, *PHP_EXTENSIONS, *P5_EXTENSIONS)
        ),
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
    if tool == "psalm":
        return _run_psalm(shard_dir)
    if tool == "flawfinder":
        return _run_flawfinder(shard_dir)
    if tool == "opengrep-sys":
        return _run_opengrep_sys(shard_dir, report)
    raise CodeBenchError(f"unknown tool {tool!r}; choose from {', '.join(SCAN_TOOLS)}")


PSALM_TIMEOUT_S = 300
PSALM_CONFIG = """<?xml version="1.0"?>
<psalm errorLevel="8" findUnusedCode="false" findUnusedBaselineEntry="false" ignoreInternalFunctionFalseReturn="true"
  phpVersion="8.3" cacheDirectory="{cache}">
  <projectFiles><directory name="b"/><directory name="a"/><directory name="u"/></projectFiles>
</psalm>
"""


def _run_psalm(shard_dir: Path) -> tuple[str, float, list[Record], dict[str, int]]:
    """Psalm 6 taint analysis (MIT), one file at a time so a before-file and its after-file cannot see each other.

    ``KESTRIX_PSALM_HOME`` holds ``env`` (a PHP build, run with its own libraries) and ``psalm`` (``composer require
    vimeo/psalm``). Files Psalm cannot parse are counted as not parsed."""
    home = Path(os.environ.get("KESTRIX_PSALM_HOME", f"/scratch/{os.environ.get('USER', '')}/kestrix/php"))
    php = home / "env" / "bin" / "php"
    psalm = home / "psalm" / "vendor" / "bin" / "psalm"
    env = {**os.environ, "LD_LIBRARY_PATH": str(home / "env" / "lib"), "HOME": str(home / "home")}
    config = shard_dir / ".psalm.xml"
    config.write_text(PSALM_CONFIG.format(cache=shard_dir / ".psalm-cache"), encoding="utf-8")
    version = _version([str(php), str(psalm), "--version"]).split("@")[0]
    found: list[Record] = []
    failed: dict[str, int] = {}
    total = 0.0
    for kind in KINDS:
        for path in sorted((shard_dir / kind).glob("*")):
            if path.suffix not in PHP_EXTENSIONS:
                continue
            rel = f"{kind}/{path.name}"
            args = [
                str(php),
                "-d",
                "memory_limit=2G",
                str(psalm),
                "--taint-analysis",
                "--no-progress",
                "--no-cache",
                "--output-format=json",
                f"--config={config}",
                f"--root={shard_dir}",
                rel,
            ]
            start = time.perf_counter()
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
                    args, cwd=shard_dir, capture_output=True, text=True, timeout=PSALM_TIMEOUT_S, check=False, env=env
                )
                issues = json.loads(proc.stdout or "[]")
            except (subprocess.TimeoutExpired, ValueError):
                failed[kind] = failed.get(kind, 0) + 1
                continue
            total += time.perf_counter() - start
            records, bad = reduce_psalm(issues, rel)
            found += records
            failed[kind] = failed.get(kind, 0) + bad
    return version, total, found, {k: v for k, v in failed.items() if v}


P5_TOOLS_HOME = "KESTRIX_P5_TOOLS"  # environment variable: directory with flawfinder/, opengrep, opengrep-rules/
OPENGREP_SYS_FOLDERS = ("c", "rust", "swift")


def _p5_home() -> Path:
    return Path(os.environ.get(P5_TOOLS_HOME, f"/scratch/{os.environ.get('USER', '')}/kestrix-sys/tools"))


def reduce_flawfinder(text: str) -> list[Record]:
    """Findings of flawfinder's ``--csv`` output (one row per hit; the CWEs column maps to families)."""
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        line = int(row.get("Line") or 1)
        families = families_for_cwes(parse_cwes([row.get("CWEs") or ""]))
        rec = record(row.get("File") or "", f"flawfinder.{row.get('Name') or ''}", line, line, families)
        if rec:
            out.append(rec)
    return out


def _run_flawfinder(shard_dir: Path) -> tuple[str, float, list[Record], dict[str, int]]:
    """flawfinder (GPL-2.0), every C and C++ file of the shard in one run, default minimum level 1, offline."""
    script = _p5_home() / "flawfinder" / "flawfinder.py"
    env = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "PYTHONUTF8": "1"}
    start = time.perf_counter()
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [sys.executable, str(script), "--csv", "."],
        cwd=shard_dir,
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT_S,
        check=False,
        env=env,
    )
    seconds = time.perf_counter() - start
    if proc.returncode != 0:
        raise CodeBenchError(f"flawfinder exited {proc.returncode}: {proc.stderr.strip()[-1500:]}")
    version = "flawfinder " + _version([sys.executable, str(script), "--version"])
    return version, seconds, reduce_flawfinder(proc.stdout), {}


def reduce_opengrep_sys(report: dict[str, Any]) -> tuple[list[Record], dict[str, int]]:
    out = []
    for item in report.get("results", []):
        metadata = (item.get("extra") or {}).get("metadata") or {}
        cwe = metadata.get("cwe") or []
        families = families_for_cwes(parse_cwes(cwe if isinstance(cwe, list) else [cwe]))
        rule = str(item.get("check_id", "")).rpartition("opengrep-rules.")[2]
        rec = record(item.get("path", ""), rule, item["start"]["line"], item["end"]["line"], families)
        if rec:
            out.append(rec)
    failed: dict[str, int] = {}
    for err in report.get("errors", []):
        located = locate(str(err.get("path", "")))
        if located and re.search(r"syntax|lexical|parse", str(err.get("type", "")), re.IGNORECASE):
            failed[located[0]] = failed.get(located[0], 0) + 1
    return out, failed


def _run_opengrep_sys(shard_dir: Path, report: Path) -> tuple[str, float, list[Record], dict[str, int]]:
    """Opengrep (LGPL-2.1) with the C, Rust and Swift folders of opengrep-rules (LGPL-2.1 with the Commons Clause; the
    README says the rules are for research, testing and benchmarking), offline, one run per shard directory."""
    home = _p5_home()
    exe = home / "opengrep"
    configs = [arg for folder in OPENGREP_SYS_FOLDERS for arg in ("--config", str(home / "opengrep-rules" / folder))]
    cache = home / "home"
    env = {**os.environ, "HOME": str(cache), "XDG_CACHE_HOME": str(cache / ".cache")}
    args = [str(exe), "scan", *configs, "--json", "--output", str(report), "--quiet", "--no-git-ignore"]
    args += ["--timeout", "30", "--max-target-bytes", "1000000", "-j", "1", "."]
    start = time.perf_counter()
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        args, cwd=shard_dir, capture_output=True, text=True, timeout=TOOL_TIMEOUT_S, check=False, env=env
    )
    seconds = time.perf_counter() - start
    if proc.returncode not in (0, 1) or not report.is_file():
        raise CodeBenchError(f"opengrep exited {proc.returncode}: {proc.stderr.strip()[-1500:]}")
    found, failed = reduce_opengrep_sys(json.loads(report.read_text(encoding="utf-8")))
    version = "opengrep " + _version_env([str(exe), "--version"], env)
    return version, seconds, found, failed


def _version_env(args: list[str], env: dict[str, str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, check=True, env=env)  # noqa: S603
    return proc.stdout.strip().splitlines()[0]


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
