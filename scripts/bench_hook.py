# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Measure the Claude Code hook's latency on generated Python files of 100, 1,000 and 5,000 lines.

Run from the repo root: ``uv run python scripts/bench_hook.py [--runs 30]``. For each size it reports
p50 and p95 in milliseconds of:

- ``in-process``: ``kestrix_scan.hook.hook_response`` for an Edit (scan after the edit, plus the scan
  of the text before it), in this interpreter;
- ``pre-tool-use``: the plugin's ``kestrix_hook.py pre-tool-use`` process (the snapshot);
- ``post-tool-use``: the plugin's ``kestrix_hook.py post-tool-use`` process, which starts
  ``kestrix-scan scan --hook``; this is what the user waits for after each edit.

The files are synthetic. Nothing is sent off the machine.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from kestrix_scan import hook

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "packages"
    / "kestrix-scan"
    / "src"
    / "kestrix_scan"
    / "claude_plugin"
    / "kestrix"
    / "hooks"
    / "kestrix_hook.py"
)
SIZES = (100, 1000, 5000)
EDIT_OLD = "def tail():"
EDIT_NEW = "def tail(cmd):\n    os.system(cmd)"  # the edit introduces one high finding


def source(lines: int) -> str:
    """About ``lines`` lines of ordinary Python with a few findings, ending in ``tail``."""
    out = ["import hashlib", "import os", "import subprocess", ""]
    i = 0
    while len(out) < lines - 4:
        out += [
            f"def handler_{i}(cursor, value, path):",
            "    query = 'SELECT name FROM items WHERE id = ?'",
            "    cursor.execute(query, (value,))",
            f"    digest = hashlib.sha256(path.encode()).hexdigest()[:{i % 16 + 1}]",
            f"    subprocess.run(['echo', digest], check=True) if value == {i} else None",
            "    return value",
            "",
            "",
        ]
        i += 1
    out += [EDIT_OLD, "    return None", ""]
    return "\n".join(out)


def percentiles(samples: list[float]) -> tuple[float, float]:
    cuts = statistics.quantiles(samples, n=20, method="inclusive")
    return statistics.median(samples), cuts[18]


def timed(runs: int, prepare: Callable[[], None], action: Callable[[], object]) -> list[float]:
    samples = []
    for _ in range(runs):
        prepare()
        started = time.perf_counter()
        action()
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def machine() -> str:
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        out = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, check=False
        )
        cpu = out.stdout.strip() or cpu
    return f"{cpu}, {os.cpu_count()} logical CPUs, {platform.system()} {platform.release()}, Python {platform.python_version()}"


def measure(target: Path, size: int, runs: int, env: dict[str, str]) -> tuple[int, list[list[float]]]:
    """Line count and the in-process, pre-tool-use and post-tool-use samples for one file size."""
    text = source(size)
    after = text.replace(EDIT_OLD, EDIT_NEW, 1)
    tool_input = {"file_path": str(target), "old_string": EDIT_OLD, "new_string": EDIT_NEW}
    raw = json.dumps({"session_id": "bench", "cwd": str(target.parent), "tool_name": "Edit", "tool_input": tool_input})

    def run(event: str) -> None:
        # the plugin's own hook script, run the way Claude Code runs it; no shell
        subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT), event], input=raw, capture_output=True, text=True, env=env, check=True
        )

    def before_then_snapshot() -> None:
        write_before()
        run("pre-tool-use")
        write_after()

    def write_before() -> None:
        target.write_text(text)

    def write_after() -> None:
        target.write_text(after)

    in_process = timed(runs, write_after, lambda: hook.hook_response(raw))
    pre = timed(runs, write_before, lambda: run("pre-tool-use"))
    post = timed(runs, before_then_snapshot, lambda: run("post-tool-use"))
    if "py.os.system" not in (hook.hook_response(raw) or ""):
        raise SystemExit("the benchmark edit must introduce a finding")
    return len(after.splitlines()), [in_process, pre, post]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=30)
    args = parser.parse_args()
    bin_dir = Path(sys.executable).parent
    print(f"Machine: {machine()}")
    print(f"Runs per measurement: {args.runs}; times in ms (p50 / p95)")
    print(f"{'lines':>6}  {'in-process':>16}  {'pre-tool-use':>16}  {'post-tool-use':>16}")
    with tempfile.TemporaryDirectory(prefix="kestrix-bench-") as tmp:
        work = Path(tmp)
        env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(work / "data"), "PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin"}
        for size in SIZES:
            lines, samples = measure(work / f"bench_{size}.py", size, args.runs, env)
            cells = ["{:>7.1f} / {:>6.1f}".format(*percentiles(s)) for s in samples]
            print(f"{lines:>6}  " + "  ".join(cells))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
