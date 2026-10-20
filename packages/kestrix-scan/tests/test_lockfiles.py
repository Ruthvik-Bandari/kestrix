# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The stdlib lockfile parsers: names, versions and the line each dependency is on."""

import json

import pytest

from kestrix_scan.lockfiles import (
    Dependency,
    normalize,
    parse_package_lock,
    parse_pipfile_lock,
    parse_pnpm_lock,
    parse_requirements,
    parse_toml_lock,
    parse_yarn_lock,
    parser_for,
)


def _triples(deps: list[Dependency]) -> list[tuple[str, str, int]]:
    return [(d.name, d.version, d.line) for d in deps]


def test_requirements_checks_exact_pins_only() -> None:
    text = "\n".join(
        [
            "# comment",
            "requests==2.19.0",
            "Django[argon2] == 4.2.0 ; python_version >= '3.8'  # inline comment",
            "flask>=2.0",
            "numpy!=1.0",
            "pandas",
            "-r other.txt",
            "-e .",
            "--index-url https://example.invalid/simple",
            "pkg @ https://example.invalid/pkg.whl",
            "git+https://example.invalid/repo.git",
            "attrs===23.1.0",
            "star==1.*",
            "hashed==1.0 \\",
            "    --hash=sha256:abc",
            "after==3.0",
        ]
    )
    parsed = parse_requirements(text)
    assert _triples(parsed.dependencies) == [
        ("requests", "2.19.0", 2),
        ("Django", "4.2.0", 3),
        ("attrs", "23.1.0", 12),
        ("hashed", "1.0", 14),
        ("after", "3.0", 16),
    ]
    assert parsed.not_checked == ["flask>=2.0", "numpy!=1.0", "pandas", "star==1.*"]
    assert all(d.ecosystem == "PyPI" for d in parsed.dependencies)


UV_LOCK = """version = 1
requires-python = ">=3.10"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.19.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "from-git"
version = "1.0.0"
source = { git = "https://example.invalid/repo.git#abc" }
"""

POETRY_LOCK = """[[package]]
name = "urllib3"
version = "1.26.0"
description = ""
optional = false

[[package]]
name = "local"
version = "0.0.1"

[package.source]
type = "directory"
url = "../local"

[[package]]
name = "private"
version = "2.0"

[package.source]
type = "legacy"
url = "https://pypi.example.invalid/simple"
"""

PDM_LOCK = """[metadata]
groups = ["default"]

[[package]]
name = "idna"
version = "3.6"
"""


def test_uv_lock_skips_workspace_and_git_packages() -> None:
    assert _triples(parse_toml_lock(UV_LOCK).dependencies) == [("requests", "2.19.0", 11)]


def test_poetry_lock_keeps_registry_and_legacy_sources() -> None:
    assert _triples(parse_toml_lock(POETRY_LOCK).dependencies) == [("urllib3", "1.26.0", 2), ("private", "2.0", 16)]


def test_pdm_lock() -> None:
    assert _triples(parse_toml_lock(PDM_LOCK).dependencies) == [("idna", "3.6", 5)]


def test_broken_toml_is_reported_unsupported() -> None:
    assert parse_toml_lock("[[package]\nname=").unsupported is not None


def test_pipfile_lock() -> None:
    text = json.dumps(
        {
            "_meta": {"hash": {"sha256": "x"}},
            "default": {"requests": {"version": "==2.19.0"}, "editable": {"editable": True, "path": "."}},
            "develop": {"pytest": {"version": "==8.0.0"}},
        },
        indent=4,
    )
    parsed = parse_pipfile_lock(text)
    assert [(d.name, d.version) for d in parsed.dependencies] == [("requests", "2.19.0"), ("pytest", "8.0.0")]
    assert text.splitlines()[parsed.dependencies[0].line - 1].strip().startswith('"requests"')


def test_package_lock_v3() -> None:
    text = json.dumps(
        {
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
                "node_modules/a/node_modules/lodash": {"version": "3.0.0"},
                "node_modules/alias": {"name": "real-name", "version": "2.0.0"},
                "node_modules/linked": {"resolved": "packages/linked", "link": True},
                "packages/linked": {"name": "linked", "version": "0.0.1"},
            },
        },
        indent=2,
    )
    parsed = parse_package_lock(text)
    assert [(d.name, d.version) for d in parsed.dependencies] == [
        ("lodash", "4.17.20"),
        ("@scope/pkg", "1.0.0"),
        ("lodash", "3.0.0"),
        ("real-name", "2.0.0"),
    ]
    lines = text.splitlines()
    assert all('"node_modules/' in lines[d.line - 1] for d in parsed.dependencies)
    assert {d.ecosystem for d in parsed.dependencies} == {"npm"}


def test_package_lock_v1_is_unsupported() -> None:
    parsed = parse_package_lock(json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0"}}}))
    assert parsed.dependencies == [] and "lockfileVersion 1" in (parsed.unsupported or "")
    assert parse_package_lock("{not json").unsupported == "not valid JSON"


YARN_V1 = """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.1.2"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.1.2.tgz"
  dependencies:
    lodash "^4.17.10"

lodash@^4.17.10:
  version "4.17.10"
"""

YARN_BERRY = """__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"lodash@npm:^4.17.10, lodash@npm:^4.17.0":
  version: 4.17.10
  resolution: "lodash@npm:4.17.10"
  checksum: 10c0/abc

"left-pad@patch:left-pad@npm%3A1.0.0#./patch":
  version: 1.0.0
  resolution: "left-pad@patch:left-pad@npm%3A1.0.0#./patch::version=1.0.0"
"""


def test_yarn_v1() -> None:
    parsed = parse_yarn_lock(YARN_V1)
    assert _triples(parsed.dependencies) == [("@babel/core", "7.1.2", 5), ("lodash", "4.17.10", 11)]


def test_yarn_berry_reads_only_npm_resolutions() -> None:
    assert _triples(parse_yarn_lock(YARN_BERRY).dependencies) == [("lodash", "4.17.10", 9)]


PNPM_V9 = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}

  lodash@4.17.20:
    resolution: {integrity: sha512-y}

  react-dom@18.2.0:
    resolution: {integrity: sha512-z}

snapshots:

  lodash@4.17.20: {}

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
"""

PNPM_V6 = """lockfileVersion: '6.0'

packages:

  /lodash@4.17.20:
    resolution: {integrity: sha512-y}
    dev: false

  /@scope/pkg@1.0.0(react@18.2.0):
    resolution: {integrity: sha512-y}
"""

PNPM_V5 = """lockfileVersion: 5.4

packages:

  /lodash/4.17.20:
    resolution: {integrity: sha512-y}

  /@scope/pkg/1.0.0_react@18.2.0:
    resolution: {integrity: sha512-y}
"""


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (PNPM_V9, [("@babel/core", "7.24.0", 13), ("lodash", "4.17.20", 16), ("react-dom", "18.2.0", 19)]),
        (PNPM_V6, [("lodash", "4.17.20", 5), ("@scope/pkg", "1.0.0", 9)]),
        (PNPM_V5, [("lodash", "4.17.20", 5), ("@scope/pkg", "1.0.0", 8)]),
    ],
    ids=["v9", "v6", "v5"],
)
def test_pnpm_lock_package_keys(text: str, expected: list[tuple[str, str, int]]) -> None:
    assert _triples(parse_pnpm_lock(text).dependencies) == expected


@pytest.mark.parametrize(
    ("rel", "found"),
    [
        ("requirements.txt", True),
        ("requirements-dev.txt", True),
        ("sub/requirements_test.txt", True),
        ("requirements/base.txt", True),
        ("notes.txt", False),
        ("uv.lock", True),
        ("poetry.lock", True),
        ("pdm.lock", True),
        ("Pipfile.lock", True),
        ("web/package-lock.json", True),
        ("npm-shrinkwrap.json", True),
        ("yarn.lock", True),
        ("pnpm-lock.yaml", True),
        ("package.json", False),
        ("pyproject.toml", False),
    ],
)
def test_parser_for(rel: str, found: bool) -> None:
    assert (parser_for(rel) is not None) is found


def test_normalize() -> None:
    assert normalize("PyPI", "Demo_Pkg.Extra") == "demo-pkg-extra"
    assert normalize("npm", "@Scope/Pkg") == "@Scope/Pkg"
