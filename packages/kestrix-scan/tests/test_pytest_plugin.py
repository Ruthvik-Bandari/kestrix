# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``pytest --kestrix``: one extra item that fails on findings at or above the threshold; off by default."""

import pytest

SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
MD5 = "import hashlib\nh = hashlib.md5(b'')\n"
PASSING = "def test_ok():\n    assert True\n"


@pytest.fixture
def project(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makepyfile(test_app=PASSING, app=SHELL)
    return pytester


def test_off_by_default(project: pytest.Pytester) -> None:
    result = project.runpytest("-v")
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(["collecting ... collected 1 item"])
    result.stdout.no_fnmatch_line("*::kestrix-scan*")
    assert "--kestrix" in project.runpytest("--help").stdout.str()


def test_off_means_the_scanner_is_never_imported(project: pytest.Pytester) -> None:
    project.makeconftest(
        "import sys\n\n"
        "def pytest_sessionfinish(session):\n"
        "    loaded = sorted(m for m in sys.modules if m.startswith('kestrix_scan'))\n"
        "    print('LOADED', loaded)\n"
    )
    result = project.runpytest_subprocess("-s")
    result.assert_outcomes(passed=1)
    assert "LOADED ['kestrix_scan', 'kestrix_scan.about', 'kestrix_scan.pytest_plugin']" in result.stdout.str()


def test_findings_fail_one_item_with_the_report(project: pytest.Pytester) -> None:
    result = project.runpytest("--kestrix", "-v")
    result.assert_outcomes(passed=1, failed=1)
    result.stdout.fnmatch_lines(["*kestrix-scan FAILED*", "*4:5  HIGH  py.subprocess.shell_true  CWE-78*"])
    assert result.ret == pytest.ExitCode.TESTS_FAILED


def test_fail_on_threshold(project: pytest.Pytester) -> None:
    project.runpytest("--kestrix", "--kestrix-fail-on=critical").assert_outcomes(passed=2)
    project.makepyfile(app=MD5)
    project.runpytest("--kestrix").assert_outcomes(passed=2)
    project.runpytest("--kestrix", "--kestrix-fail-on", "medium").assert_outcomes(passed=1, failed=1)


def test_honours_tool_kestrix(project: pytest.Pytester) -> None:
    project.makepyprojecttoml('[tool.kestrix]\nrules.disable = ["py.subprocess"]\n')
    project.runpytest("--kestrix").assert_outcomes(passed=2)
    project.makepyprojecttoml('[tool.kestrix]\nfail-on = "none"\n')
    project.runpytest("--kestrix").assert_outcomes(passed=2)
    project.runpytest("--kestrix", "--kestrix-fail-on=high").assert_outcomes(passed=1, failed=1)


def test_bad_config_fails_the_item_with_the_reason(project: pytest.Pytester) -> None:
    project.makepyprojecttoml('[tool.kestrix]\nrules.disable = ["py.subproces"]\n')
    result = project.runpytest("--kestrix")
    result.assert_outcomes(passed=1, failed=1)
    result.stdout.fnmatch_lines(["*Rejected (invalid_input)*did you mean 'py.subprocess.'*"])


def test_bad_level_is_a_usage_error(project: pytest.Pytester) -> None:
    result = project.runpytest("--kestrix", "--kestrix-fail-on=severe")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
