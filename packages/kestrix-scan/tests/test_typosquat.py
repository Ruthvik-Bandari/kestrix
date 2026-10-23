# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Typosquat detection: the popular-name snapshot, the rules, the install guard's warning, the allow-list, routing."""

import json
import time
from pathlib import Path
from typing import Any

import osv_support as osv
import pytest

from kestrix_scan import hook, popular
from kestrix_scan.config import from_mapping
from kestrix_scan.errors import Rejected
from kestrix_scan.install_guard import Requested, typosquat_warnings


def _decide(command: str, cwd: Path | None = None) -> dict[str, Any] | None:
    payload: dict[str, Any] = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
    if cwd is not None:
        payload["cwd"] = str(cwd)
    out = hook.hook_response(json.dumps(payload))
    return json.loads(out)["hookSpecificOutput"] if out else None


def _swappable(name: str) -> int | None:
    head = name.partition("/")[0]  # a Packagist vendor or an npm scope is swapped, never the package after it
    for i in range(3, len(head) - 1):
        if head[i] != head[i + 1] and head[i].isalpha() and head[i + 1].isalpha():
            return i
    return None


def _swap(name: str) -> str:
    """Swap the first adjacent pair of different letters after the third character: a squat the rules must catch."""
    i = _swappable(name)
    assert i is not None, name
    return name[:i] + name[i + 1] + name[i] + name[i + 2 :]


def _top(ecosystem: str, wanted: int = 1) -> str:
    """The most popular listed name of an ecosystem that is long enough to be swapped."""
    names = popular._index(ecosystem)
    assert names is not None
    candidates = [n for n in names.names if len(n.partition("/")[0]) >= 7 and _swappable(n) is not None]
    return candidates[wanted - 1]


def test_snapshot_is_bundled_with_date_sources_and_enough_names() -> None:
    generated, counts = popular.snapshot_info()
    assert len(generated) == 10 and generated.startswith("20")
    assert set(counts) == set(popular.ECOSYSTEMS)
    assert all(count >= 4_000 for count in counts.values())
    sources = json.loads((Path(popular.__file__).parent / popular.SNAPSHOT).read_text(encoding="utf-8"))["sources"]
    assert all(entry["url"].startswith("https://") and entry["licence"] for entry in sources.values())


def test_the_two_documented_squats_warn() -> None:
    swapped = popular.suspect("PyPI", "reqeusts")
    assert swapped is not None and swapped.target == "requests" and "swapped" in swapped.reason
    extra = popular.suspect("PyPI", "colourama")
    assert extra is not None and extra.target == "colorama" and "`u` is added" in extra.reason


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("PyPI", "requests"),
        ("PyPI", "numpy"),
        ("npm", "express"),
        ("npm", "react"),
        ("PyPI", "Requests"),
        ("PyPI", "py"),
    ],
)
def test_popular_and_short_names_are_silent(ecosystem: str, name: str) -> None:
    assert popular.suspect(ecosystem, name) is None


@pytest.mark.parametrize("ecosystem", popular.ECOSYSTEMS)
def test_no_listed_name_is_flagged(ecosystem: str) -> None:
    index = popular._index(ecosystem)
    assert index is not None
    assert [name for name in index.names if popular.suspect(ecosystem, name)] == []


@pytest.mark.parametrize(
    ("ecosystem", "name", "target", "rule"),
    [
        ("PyPI", "requets", "requests", "edit"),  # dropped letter
        ("PyPI", "reqeusts", "requests", "edit"),  # swap
        ("PyPI", "requessts", "requests", "edit"),  # doubled letter
        ("PyPI", "requesys", "requests", "edit"),  # neighbouring key
        ("PyPI", "reque5ts", "requests", "homoglyph"),
        ("PyPI", "pyth0n-dateutil", "python-dateutil", "homoglyph"),
        ("PyPI", "pythondateutil", "python-dateutil", "separator"),
        ("PyPI", "python-requests", "requests", "affix"),
        ("PyPI", "requests-py", "requests", "affix"),
        ("npm", "expres", "express", "edit"),
        ("npm", "crossenv", "cross-env", "separator"),
        ("npm", "lodash-js", "lodash", "affix"),
        ("npm", "node-lodash", "lodash", "affix"),
        ("npm", "@typs/node", "@types/node", "edit"),  # scope typo
        ("crates.io", "serd-json", "serde-json", "edit"),
    ],
)
def test_squat_rules(ecosystem: str, name: str, target: str, rule: str) -> None:
    found = popular.suspect(ecosystem, name)
    assert found is not None, name
    assert (found.target, found.rule) == (target, rule)


def test_scopes_digits_and_ecosystems() -> None:
    assert popular.suspect("npm", "@types/nod") is None  # the owner's own scope: nobody else can publish there
    assert popular.suspect("npm", "@babel/corf") is None
    assert popular.suspect("PyPI", "boto4") is None  # a digit is added or changed: a sibling, not a squat
    assert popular.suspect("PyPI", "boto") is None
    assert popular.suspect("RubyGems", "reqeusts") is None  # no popular list for these
    assert popular.suspect("Go", "github.com/gin-gonic/gim") is None
    assert popular.suspect("NuGet", "Newtonsoft.Jsno") is None
    # Normalization: PEP 503 folds case and separators, so these are the listed names themselves.
    assert popular.suspect("PyPI", "Python_Dateutil") is None
    assert popular.suspect("PyPI", "python.dateutil") is None


def test_unreadable_snapshot_means_silence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(popular, "_snapshot", lambda: {})
    popular._index.cache_clear()
    try:
        assert popular.suspect("PyPI", "reqeusts") is None
        assert popular.snapshot_info() == ("", {})
    finally:
        popular._index.cache_clear()


def test_a_check_takes_under_20_ms() -> None:
    names = [_swap(_top(eco, rank)) for eco in popular.ECOSYSTEMS for rank in range(1, 41)] + ["totally-unrelated-name"]
    popular.suspect("PyPI", "warm-up-call")  # loads the snapshot and builds the indexes once
    for eco in popular.ECOSYSTEMS:
        popular.suspect(eco, "warm-up-call")
    started = time.perf_counter()
    for name in names:
        for eco in popular.ECOSYSTEMS:
            popular.suspect(eco, name)
    per_check = (time.perf_counter() - started) / (len(names) * len(popular.ECOSYSTEMS))
    assert per_check < 0.020


# ----- the install guard


def test_warning_names_the_likely_package_and_never_blocks() -> None:
    decision = _decide("pip install reqeusts")
    assert decision is not None and "permissionDecision" not in decision
    context = decision["additionalContext"]
    assert "`reqeusts` (PyPI)" in context and "typosquat of `requests`" in context
    assert "did you mean `requests`?" in context and "install-allow" in context
    assert "No local OSV index" in context  # no index here: the advisory check could not run, and the note says so
    assert "not checked for advisories" in context
    assert _decide("pip install requests numpy") is None
    assert _decide("npm i express") is None


def test_an_index_with_data_adds_the_no_advisory_statement(isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index)
    context = (_decide("pip install colourama") or {})["additionalContext"]
    assert "The local index lists no advisory for it." in context and "did you mean `colorama`?" in context


def test_a_name_with_an_advisory_is_not_a_typosquat_warning(isolated_osv_index: Path) -> None:
    records = [osv.advisory("GHSA-aaaa-bbbb-cccc", "PyPI", "reqeusts", versions=["1.0"], cwes=["CWE-79"])]
    osv.build(isolated_osv_index, ecosystems={"PyPI": records, "npm": []})
    assert _decide("pip install reqeusts") is None


def test_known_malware_is_still_denied_not_warned(isolated_osv_index: Path) -> None:
    records = [osv.advisory("MAL-2026-1", "PyPI", "reqeusts", versions=["1.0"])]
    osv.build(isolated_osv_index, ecosystems={"PyPI": records, "npm": []})
    decision = _decide("pip install reqeusts==1.0")
    assert decision is not None and decision["permissionDecision"] == "deny"


def test_allow_list_and_broken_settings(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert _decide("pip install reqeusts", project) is not None
    (project / "pyproject.toml").write_text('[tool.kestrix]\ninstall-allow = ["Reqeusts", "@mine/*"]\n')
    assert _decide("pip install reqeusts", project) is None
    assert _decide("pip install colourama", project) is not None  # only the listed names
    (project / "pyproject.toml").write_text('[tool.kestrix]\ninstall-allow = ["@typs/*"]\n')
    assert _decide("npm i @typs/node", project) is None
    (project / "pyproject.toml").write_text("[tool.kestrix]\ninstall-allow = 3\n")
    assert _decide("pip install reqeusts", project) is not None  # broken settings: the guard stays on
    with pytest.raises(Rejected):
        from_mapping({"install-allow": 3}, base=project)
    assert from_mapping({"install-allow": ["a", "b*"]}, base=project).install_allow == ("a", "b*")


def test_project_and_env_opt_outs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[tool.kestrix]\nclaude.install-guard = false\n")
    assert _decide("pip install reqeusts", project) is None
    monkeypatch.setenv("KESTRIX_INSTALL_GUARD", "0")
    assert _decide("pip install reqeusts") is None


@pytest.mark.parametrize(
    ("template", "ecosystem"),
    [
        ("pip install {}", "PyPI"),
        ("pip3 install -U {}==1.0.0", "PyPI"),
        ("python3 -m pip install {}", "PyPI"),
        ("uv pip install {}", "PyPI"),
        ("uv add {}", "PyPI"),
        ("npm install {}", "npm"),
        ("npm i -D {}@1.2.3", "npm"),
        ("pnpm add {}", "npm"),
        ("yarn add {}", "npm"),
        ("bun add {}", "npm"),
        ("composer require {}", "Packagist"),
        ("cargo add {}", "crates.io"),
    ],
)
def test_each_install_command_routes_to_its_ecosystem(template: str, ecosystem: str) -> None:
    squat = _swap(_top(ecosystem, 5))
    target = _top(ecosystem, 5)
    context = (_decide(template.format(squat)) or {})["additionalContext"]
    assert f"`{squat}` ({ecosystem})" in context and f"did you mean `{target}`?" in context
    assert (_decide(template.format(target)) or {}).get("additionalContext") is None


@pytest.mark.parametrize(
    "command", ["gem install reqeusts", "go get github.com/gin-gonic/gim", "dotnet add package Newtonsoft.Jsno"]
)
def test_ecosystems_without_a_popular_list_stay_silent(command: str) -> None:
    assert _decide(command) is None


def test_many_squats_are_summarized_and_the_message_is_bounded() -> None:
    squats = [Requested("PyPI", _swap(_top("PyPI", rank)), None) for rank in range(1, 13)]
    lines = typosquat_warnings(squats)
    assert len(lines) == 6 and lines[-1].endswith("more possible typosquats.")
    command = "pip install " + " ".join(item.name for item in squats)
    assert len((_decide(command) or {})["additionalContext"]) <= 2_000
