# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Record the expected output of each step of the Claude Code demo in ``docs/demo/expected/``.

Run from the repo root: ``uv run python scripts/build_demo_expected.py``. With ``--check`` it writes
nothing and exits 1 when a committed file differs from what the current scanner and hook script produce;
``tests/integrations/test_plugin_demo.py`` runs that check, so the demo never shows stale output.

Each step builds the demo project with ``docs/demo/setup_demo.py`` in a temporary directory, then runs
the plugin's real hook script (``hooks/kestrix_hook.py``) with the hook JSON that Claude Code sends for
that step, with the ``kestrix-scan`` of this environment first on PATH. Temporary paths are replaced by
``<demo>`` so the files are the same on every machine.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "docs" / "demo"
EXPECTED = DEMO / "expected"
HOOK = REPO / "packages/kestrix-scan/src/kestrix_scan/claude_plugin/kestrix/hooks/kestrix_hook.py"
SESSION = "kestrix-demo-session"

# Step 2 of docs/demo/prompts.md asks Claude to create this file with this code.
EXPORT_PY = """import os


def export_notes(name):
    os.system("cp notes.db exports/" + name)
"""


def _setup_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("setup_demo", DEMO / "setup_demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hook(event: str, payload: dict[str, object], project: Path, data: Path) -> str:
    env = {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")]),
        "CLAUDE_PLUGIN_DATA": str(data),
        "CLAUDE_PROJECT_DIR": str(project),
        "HOME": str(data),
    }
    # A fixed argument list: the hook script of this repository and one event name.
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(HOOK), event],
        input=json.dumps(payload).encode(),
        capture_output=True,
        cwd=project,
        env=env,
        timeout=60,
        check=True,
    )
    return result.stdout.decode()


def _pretty(output: str, project: Path) -> str:
    text = json.dumps(json.loads(output), indent=2, ensure_ascii=False) + "\n"
    return text.replace(str(project), "<demo>")


def render() -> dict[str, str]:
    """File name in ``docs/demo/expected/`` -> its content."""
    setup = _setup_module()
    with tempfile.TemporaryDirectory() as tmp:
        project = setup.setup(Path(tmp).resolve() / "demo")
        data = Path(tmp).resolve() / "plugin-data"
        data.mkdir()
        base = {"session_id": SESSION, "cwd": str(project)}
        env = {**os.environ, "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])}
        # The scanner's own command, as /kestrix:scan runs it (exit 1: high findings).
        scan = subprocess.run(  # noqa: S603
            [str(Path(sys.executable).parent / "kestrix-scan"), "."],
            capture_output=True,
            cwd=project,
            env=env,
            timeout=60,
            check=False,
        )
        assert scan.returncode == 1, scan.stderr
        out = {"scan.txt": scan.stdout.decode()}

        start = _hook("session-start", {**base, "hook_event_name": "SessionStart", "source": "startup"}, project, data)
        out["session-start.json"] = _pretty(start, project)

        target = project / "export.py"
        write = {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": EXPORT_PY},
        }
        assert _hook("pre-tool-use", write, project, data) == ""
        target.write_text(EXPORT_PY, encoding="utf-8")
        post = {**write, "hook_event_name": "PostToolUse", "tool_response": {"type": "create", "filePath": str(target)}}
        out["post-tool-use.json"] = _pretty(_hook("post-tool-use", post, project, data), project)

        # If Claude tried to finish without fixing export.py, the Stop gate (on via .kestrix.json) blocks once.
        stop = {**base, "hook_event_name": "Stop", "stop_hook_active": False}
        out["stop.json"] = _pretty(_hook("stop", stop, project, data), project)
    return out


def main() -> int:
    files = render()
    if "--check" in sys.argv[1:]:
        stale = [
            name
            for name, text in files.items()
            if not (EXPECTED / name).is_file() or (EXPECTED / name).read_text(encoding="utf-8") != text
        ]
        extra = sorted(p.name for p in EXPECTED.glob("*") if p.name not in files) if EXPECTED.is_dir() else []
        if stale or extra:
            print(
                f"docs/demo/expected is out of date ({stale + extra}); run scripts/build_demo_expected.py",
                file=sys.stderr,
            )
            return 1
        return 0
    EXPECTED.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (EXPECTED / name).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
