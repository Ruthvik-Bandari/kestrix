# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``scripts/ab_eval.py``: the command it runs and the metrics it computes from a result document.

The result documents here are synthetic and follow the shape the script reads (see its docstring); a real one must
be checked with the one-case run in ``evals/README.md``. No model is called.
"""

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "packages" / "kestrix-scan" / "plugin-repo" / "scripts" / "ab_eval.py"
VULNERABLE = (
    "import subprocess\n\n\ndef archive_folder(name):\n    subprocess.run(f'tar czf {name}.tgz {name}', shell=True)\n"
)
SAFE = "import subprocess\n\n\ndef archive_folder(name):\n    subprocess.run(['tar', 'czf', f'{name}.tgz', name], check=True)\n"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ab_eval", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ab = _load()


def run(
    passed: dict[str, bool], *, tokens: int | None = 1000, turns: int | None = 4, workspace: Path | None = None
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "error": None,
        "graders": [{"name": name, "passed": ok} for name, ok in passed.items()],
    }
    if tokens is not None:
        document["usage"] = {"inputTokens": tokens, "outputTokens": 0}
    if turns is not None:
        document["numTurns"] = turns
    if workspace is not None:
        document["workspace"] = str(workspace)
    return document


def results(tmp_path: Path) -> dict[str, Any]:
    bad, good = tmp_path / "bad", tmp_path / "good"
    for folder, text in ((bad, VULNERABLE), (good, SAFE)):
        folder.mkdir()
        (folder / "archive.py").write_text(text)
    written = {"file-written": True, "feature-present": True}
    shipped = {**written, "final-clean": False, "no-vulnerable-write": False}
    fixed = {**written, "final-clean": True, "no-vulnerable-write": False}
    clean = {**written, "final-clean": True, "no-vulnerable-write": True}
    quiet = {"file-written": True, "single-write": True, "no-edit": True}
    noisy = {"file-written": True, "single-write": True, "no-edit": False}
    return {
        "claudeVersion": "2.1.999",
        "costUsd": 12.5,
        "cases": [
            {
                "name": "ab-shell",
                "arms": {
                    "with": [
                        run(fixed, workspace=good, turns=6),
                        run(fixed, workspace=good, turns=6),
                        run(shipped, workspace=bad),
                    ],
                    "without": [run(shipped, workspace=bad), run(shipped, workspace=bad), run(clean, workspace=good)],
                },
            },
            {
                "name": "ab-safe-git",
                "arms": {"with": [run(noisy), run(quiet)], "without": [run(quiet), run(quiet)]},
            },
        ],
    }


def test_the_eval_command_is_the_documented_paired_run() -> None:
    argv = ab.command(5, "some-model", 40.0, Path("evals/results/ab"))
    assert argv[:5] == ["claude", "plugin", "eval", ".", "--tag"] and argv[5] == "ab"
    assert argv[argv.index("--runs") + 1] == "5"
    assert argv[argv.index("--ablation") + 1] == "with-without"
    assert argv[argv.index("--allow-tools") + 1 : argv.index("--allow-tools") + 3] == ["Write", "Edit"]
    for flag in ("--trust-plugin", "--keep-temp", "--no-publish"):
        assert flag in argv
    assert argv[argv.index("--max-cost-usd") + 1] == "40"
    assert argv[argv.index("--model") + 1] == "some-model"
    assert argv[argv.index("--json") + 1] == "evals/results/ab/results.json"
    assert "--model" not in ab.command(5, None, 40.0, Path("x"))


def test_dry_run_prints_the_command_and_calls_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    assert ab.main(["run", "--runs", "2", "--dry-run"]) == 0
    assert capsys.readouterr().out.startswith("claude plugin eval . --tag ab --runs 2 --ablation with-without")


def test_metrics_per_arm(tmp_path: Path) -> None:
    summary = ab.summarize(results(tmp_path), scan=False, files={})
    with_plugin, without = summary["with"], summary["without"]
    assert (with_plugin["written"], with_plugin["shipped"]) == (3, 1)
    assert (without["written"], without["shipped"]) == (3, 2)
    assert (with_plugin["wrote_vuln"], with_plugin["fixed"]) == (
        3,
        2,
    )  # two of the three vulnerable first writes were fixed
    assert (without["wrote_vuln"], without["fixed"]) == (2, 0)
    assert (with_plugin["ctl_runs"], with_plugin["ctl_bad"]) == (2, 1)
    assert (without["ctl_runs"], without["ctl_bad"]) == (2, 0)
    assert with_plugin["turns"] == [6.0, 6.0, 4.0, 4.0, 4.0] and with_plugin["tokens"] == [1000.0] * 5


def test_scanner_cross_check_reads_the_final_files(tmp_path: Path) -> None:
    if shutil.which("kestrix-scan") is None:
        pytest.skip("needs kestrix-scan on PATH")
    summary = ab.summarize(results(tmp_path), scan=True, files={"ab-shell": "archive.py"})
    assert (summary["with"]["scan_n"], summary["with"]["scan_shipped"]) == (3, 1)
    assert (summary["without"]["scan_n"], summary["without"]["scan_shipped"]) == (3, 2)


def test_report_text_and_missing_fields_are_n_a(tmp_path: Path) -> None:
    document = results(tmp_path)
    for case in document["cases"]:
        for arm in case["arms"].values():
            for item in arm:
                item.pop("usage", None)
                item.pop("numTurns", None)
                item.pop("workspace", None)
    summary = ab.summarize(document, scan=True, files={"ab-shell": "archive.py"})
    text = ab.render(document, summary, scan=True)
    assert "| Vulnerable code shipped | 1/3 (33%) | 2/3 (67%) |" in text
    assert "| False interruption on safe tasks | 1/2 (50%) | 0/2 (0%) |" in text
    assert "| Tokens per task (mean) | n/a | n/a |" in text and "| Turns per task (mean) | n/a | n/a |" in text
    assert "by `kestrix-scan` on the final file | n/a | n/a |" in text  # no workspace paths in the results
    assert "2.1.999" in text and "| `ab-shell` | 1/3 (33%) | 2/3 (67%) |" in text


def test_results_go_between_the_markers_of_the_template(tmp_path: Path) -> None:
    template = tmp_path / "plugin-ab.md"
    template.write_text("# Title\n\n<!-- results:start -->\n\nNot yet run.\n\n<!-- results:end -->\n\nAfter.\n")
    source = tmp_path / "results.json"
    source.write_text(json.dumps(results(tmp_path)))
    assert ab.main(["report", str(source), "--out", str(template)]) == 0
    text = template.read_text()
    assert text.startswith("# Title") and text.endswith("After.\n") and "Not yet run." not in text
    assert "| Metric | With plugin | Without plugin |" in text
    again = text
    assert ab.main(["report", str(source), "--out", str(template)]) == 0
    assert template.read_text() == again  # rerunning replaces the block, never stacks a second one
    bare = tmp_path / "bare.md"
    bare.write_text("no markers\n")
    with pytest.raises(SystemExit, match="marker"):
        ab.main(["report", str(source), "--out", str(bare)])


def test_the_docs_template_is_a_not_yet_run_page_with_markers() -> None:
    text = (REPO / "docs" / "benchmarks" / "plugin-ab.md").read_text(encoding="utf-8")
    assert "**Status: not yet run. No effectiveness numbers are claimed.**" in text
    assert text.count("<!-- results:start -->") == text.count("<!-- results:end -->") == 1
    assert "Not yet run." in text.split("<!-- results:start -->")[1]
