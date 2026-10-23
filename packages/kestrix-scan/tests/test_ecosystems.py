# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Packagist, Go, crates.io, Maven, RubyGems, NuGet and Pub: version ordering, lockfile parsers, scans."""

import json
from pathlib import Path

import osv_support as osv
import pytest

from kestrix_scan import deps, scan
from kestrix_scan.cli import render
from kestrix_scan.ecoversions import composer_key, maven_key, nuget_key, rubygems_key
from kestrix_scan.lockfiles import Dependency, ecosystem_for_file, parser_for
from kestrix_scan.lockfiles_more import (
    parse_bun_lock,
    parse_cargo_lock,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_go_sum,
    parse_gradle_lockfile,
    parse_nuget_lock,
    parse_pom,
    parse_pubspec_lock,
)
from kestrix_scan.versions import KEYS, affects, fixed_versions, is_affected, next_fixed, version_key

# ----- version ordering: each list is strictly increasing; the equal groups compare equal

ORDERS = {
    "Packagist": [
        "1.0.0-dev",
        "1.0.0-alpha1",
        "1.0.0-alpha2",
        "1.0.0-beta1",
        "1.0.0-RC1",
        "1.0.0-RC2",
        "1.0.0",
        "1.0.0-p1",
        "1.0.1-dev",
        "1.0.1",
        "v1.1.0",
        "1.10.0",
        "2.0",
        "2.0.0.1",
    ],
    "RubyGems": [
        "1.0.0.a",
        "1.0.0.b",
        "1.0.0.pre",
        "1.0-1",
        "1.0.0.rc1",
        "1.0",
        "1.0.1",
        "1.0.10",
        "1.1.a",
        "1.1",
        "2",
    ],
    "NuGet": [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.0.1",
        "1.0.1",
        "1.10.0",
    ],
    # The qualifier lists of Maven's own ComparableVersion tests.
    "Maven": [
        "1-alpha2snapshot",
        "1-alpha2",
        "1-alpha-123",
        "1-beta-2",
        "1-beta123",
        "1-m2",
        "1-m11",
        "1-rc",
        "1-cr2",
        "1-rc123",
        "1-SNAPSHOT",
        "1",
        "1-sp",
        "1-sp2",
        "1-sp123",
        "1-abc",
        "1-def",
        "1-pom-1",
        "1-1-snapshot",
        "1-1",
        "1-2",
        "1-123",
    ],
    "Go": [
        "0.0.0-20200101000000-aaaaaaaaaaaa",
        "0.0.0-20210101000000-bbbbbbbbbbbb",
        "0.1.0",
        "1.2.3",
        "1.2.4-0.20210101000000-cccccccccccc",
        "1.2.4",
        "v1.10.0",
        "2.0.0+incompatible",
    ],
    "crates.io": ["0.9.9", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0", "1.0.1", "1.10.0"],
    "Pub": ["0.9.0", "1.0.0-dev.1", "1.0.0", "1.0.1", "2.0.0"],
}
EQUAL = {
    "Packagist": [("1", "1.0.0"), ("v1.2.3", "1.2.3.0"), ("1.0.0-stable", "1.0.0")],
    "RubyGems": [("1", "1.0.0")],
    "NuGet": [("1.0", "1.0.0.0"), ("1.0.0-BETA", "1.0.0-beta"), ("1.0.0+build5", "1.0.0")],
    "Maven": [("1", "1.0"), ("1", "1-ga"), ("1.0.0", "1-final"), ("1-a1", "1-alpha-1"), ("5.3.20.RELEASE", "5.3.20")],
    "Go": [("1.2.3", "v1.2.3"), ("v1.2.3+incompatible", "1.2.3")],
}


@pytest.mark.parametrize("ecosystem", sorted(ORDERS))
def test_version_order(ecosystem: str) -> None:
    keys = [KEYS[ecosystem](text) for text in ORDERS[ecosystem]]
    assert None not in keys
    for low, high, low_text, high_text in zip(keys, keys[1:], ORDERS[ecosystem], ORDERS[ecosystem][1:], strict=False):
        assert low < high, f"{ecosystem}: {low_text} should sort before {high_text}"
        assert not high <= low


@pytest.mark.parametrize(("ecosystem", "pair"), [(e, p) for e, pairs in EQUAL.items() for p in pairs])
def test_equal_versions(ecosystem: str, pair: tuple[str, str]) -> None:
    assert KEYS[ecosystem](pair[0]) == KEYS[ecosystem](pair[1])


def test_maven_real_world_versions() -> None:
    assert maven_key("4.12") < maven_key("4.13") < maven_key("4.13.1")  # type: ignore[operator]
    assert maven_key("1.2.3") < maven_key("1.10.0")  # type: ignore[operator]
    assert maven_key("3.0.0-M1") < maven_key("3.0.0-RC1") < maven_key("3.0.0")  # type: ignore[operator]
    assert maven_key("2.0.0.Final") == maven_key("2.0.0")
    assert maven_key("5.3.20.RELEASE") < maven_key("5.3.21.RELEASE")  # type: ignore[operator]
    assert maven_key("1.0") < maven_key("1.0.1-SNAPSHOT") < maven_key("1.0.1")  # type: ignore[operator]


@pytest.mark.parametrize(
    ("key", "text"),
    [
        (maven_key, ""),
        (maven_key, "[1.0,2.0)"),
        (maven_key, "1.0 beta"),
        (maven_key, "x" * 500),
        (composer_key, "dev-main"),
        (composer_key, "latest"),
        (rubygems_key, "1..2"),
        (rubygems_key, "abc"),
        (nuget_key, "1.0.0.0.0"),
        (nuget_key, "one"),
    ],
)
def test_versions_that_are_not_versions_do_not_parse(key: object, text: str) -> None:
    assert key(text) is None  # type: ignore[operator]


def test_unparseable_versions_make_the_answer_unknown_not_clean() -> None:
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
    assert affects("Maven", "1.0", ranges, []) is True
    assert affects("Maven", "2.0", ranges, []) is False
    assert affects("Maven", "[1.0,2.0)", ranges, []) is None  # the dependency's version cannot be compared
    assert affects("Maven", "[1.0,2.0)", [], ["[1.0,2.0)"]) is True  # but a verbatim listing still matches
    assert affects("Maven", "[1.0,2.0)", [], ["1.0"]) is False  # nothing to compare: not affected
    broken = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "(2.0]"}]}]
    assert affects("Maven", "1.0", broken, []) is None  # an event that cannot be compared
    assert affects("Packagist", "1.0.0", ranges, []) is True
    assert not is_affected("Maven", "[1.0,2.0)", ranges, [])  # certain answers only


def test_fixed_version_selection_in_new_ecosystems() -> None:
    ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [{"introduced": "1.0"}, {"fixed": "1.2.5.RELEASE"}, {"introduced": "2.0"}, {"fixed": "2.0.3"}],
        }
    ]
    assert fixed_versions(ranges) == ["1.2.5.RELEASE", "2.0.3"]
    assert next_fixed("Maven", "1.2.0.RELEASE", fixed_versions(ranges)) == "1.2.5.RELEASE"
    assert next_fixed("Maven", "2.0.1", fixed_versions(ranges)) == "2.0.3"
    assert version_key("Maven", "1.0") == maven_key("1.0")
    assert version_key("Maven", "[bad]") == maven_key("0")
    assert is_affected("Maven", "1.1", ranges, []) and not is_affected("Maven", "1.5", ranges, [])
    assert is_affected("Maven", "2.0.2", ranges, []) and not is_affected("Maven", "2.0.3", ranges, [])


# ----- parsers


def _triples(found: list[Dependency]) -> list[tuple[str, str, str, int]]:
    return [(d.ecosystem, d.name, d.version, d.line) for d in found]


def _line_of(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


COMPOSER_LOCK = """{
    "_readme": ["This file locks the dependencies of your project to a known state"],
    "packages": [
        {
            "name": "acme\\/php-lib",
            "version": "v2.3.1",
            "source": {"type": "git", "url": "https://example.invalid/acme/php-lib.git"}
        },
        {
            "name": "Monolog\\/Monolog",
            "version": "3.5.0"
        },
        {
            "name": "acme\\/branchy",
            "version": "dev-main"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit\\/phpunit",
            "version": "10.5.1"
        }
    ]
}
"""


def test_composer_lock() -> None:
    parsed = parse_composer_lock(COMPOSER_LOCK)
    assert _triples(parsed.dependencies) == [
        ("Packagist", "acme/php-lib", "v2.3.1", 5),
        ("Packagist", "Monolog/Monolog", "3.5.0", 10),
        ("Packagist", "phpunit/phpunit", "10.5.1", 20),
    ]
    assert parsed.not_checked == ["acme/branchy (dev-main): a branch, not a release"]
    assert parse_composer_lock("not json").unsupported == "not valid JSON"


GO_MOD = """module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/text v0.3.7 // indirect
	example.com/local v1.0.0
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4
)

require github.com/pkg/errors v0.9.1 // indirect

exclude github.com/bad/mod v1.0.0

replace example.com/local => ../local

replace (
	golang.org/x/text v0.3.7 => golang.org/x/text v0.3.8
)
"""


def test_go_mod_applies_replace_and_skips_local_paths() -> None:
    assert _triples(parse_go_mod(GO_MOD).dependencies) == [
        ("Go", "github.com/gin-gonic/gin", "v1.9.0", 6),
        ("Go", "golang.org/x/text", "v0.3.8", 7),
        ("Go", "golang.org/x/net", "v0.0.0-20210405180319-a5a99cb37ef4", 9),
        ("Go", "github.com/pkg/errors", "v0.9.1", 12),
    ]


GO_SUM = """github.com/a/b v1.0.0 h1:aaaa=
github.com/a/b v1.0.0/go.mod h1:bbbb=
github.com/a/b v1.2.0 h1:cccc=
github.com/a/b v1.2.0/go.mod h1:dddd=
github.com/only/mod v0.5.0/go.mod h1:eeee=
github.com/c/d v2.0.0+incompatible h1:ffff=
github.com/c/d v1.9.0 h1:gggg=
"""


def test_go_sum_keeps_the_highest_hashed_version_of_each_module() -> None:
    assert _triples(parse_go_sum(GO_SUM).dependencies) == [
        ("Go", "github.com/a/b", "v1.2.0", 3),
        ("Go", "github.com/c/d", "v2.0.0+incompatible", 6),
    ]


CARGO_LOCK = """# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "gitdep"
version = "0.2.0"
source = "git+https://example.invalid/x?rev=abc#abc"

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "serde"
version = "0.9.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


def test_cargo_lock_reads_registry_crates_only() -> None:
    assert _triples(parse_cargo_lock(CARGO_LOCK).dependencies) == [
        ("crates.io", "serde", "1.0.100", 14),
        ("crates.io", "serde", "0.9.15", 20),
    ]


POM = """<project>
  <properties>
    <spring.version>5.3.20.RELEASE</spring.version>
    <nested>${spring.version}</nested>
  </properties>
  <!-- <dependency><groupId>commented</groupId><artifactId>out</artifactId><version>1.0</version></dependency> -->
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.managed</groupId>
        <artifactId>bom-entry</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${nested}</version>
      <exclusions>
        <exclusion><groupId>commons-logging</groupId><artifactId>commons-logging</artifactId></exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>org.acme</groupId>
      <artifactId>acme-core</artifactId>
    </dependency>
    <dependency>
      <groupId>org.range</groupId>
      <artifactId>ranged</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
    <dependency>
      <groupId>org.unresolved</groupId>
      <artifactId>thing</artifactId>
      <version>${missing.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>[4.12]</version>
    </dependency>
  </dependencies>
</project>
"""


def test_pom_resolves_properties_and_lists_what_it_cannot_check() -> None:
    parsed = parse_pom(POM)
    assert _triples(parsed.dependencies) == [
        ("Maven", "org.managed:bom-entry", "9.9.9", 9),
        ("Maven", "org.springframework:spring-core", "5.3.20.RELEASE", 17),
        ("Maven", "junit:junit", "4.12", 39),
    ]
    assert parsed.not_checked == [
        "org.acme:acme-core (version managed by a parent POM or BOM)",
        "org.range:ranged (version [1.0,2.0))",
        "org.unresolved:thing (version ${missing.version})",
    ]


def test_gradle_lockfile() -> None:
    text = (
        "# This is a Gradle generated file for dependency locking.\n"
        "org.acme:acme-core:1.2.0=compileClasspath,runtimeClasspath\n"
        "org.acme:acme-core:1.2.0=testCompileClasspath\n"
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n"
        "empty=annotationProcessor\n"
    )
    assert _triples(parse_gradle_lockfile(text).dependencies) == [
        ("Maven", "org.acme:acme-core", "1.2.0", 2),
        ("Maven", "com.google.guava:guava", "31.1-jre", 4),
    ]


GEMFILE_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.8)
    rails (7.1.0.rc1)

GIT
  remote: https://example.invalid/x.git
  revision: abc
  specs:
    private (0.1.0)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails
"""


def test_gemfile_lock() -> None:
    assert _triples(parse_gemfile_lock(GEMFILE_LOCK).dependencies) == [
        ("RubyGems", "nokogiri", "1.15.4", 4),
        ("RubyGems", "rack", "2.2.8", 6),
        ("RubyGems", "rails", "7.1.0.rc1", 7),
    ]


NUGET_LOCK = """{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.1, )",
        "resolved": "13.0.1",
        "contentHash": "x"
      },
      "MyProject.Core": {
        "type": "Project"
      }
    },
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.1"
      },
      "Acme.Core": {
        "type": "Transitive",
        "resolved": "3.0.0"
      }
    }
  }
}
"""


def test_nuget_lock_dedupes_frameworks_and_skips_projects() -> None:
    assert _triples(parse_nuget_lock(NUGET_LOCK).dependencies) == [
        ("NuGet", "Newtonsoft.Json", "13.0.1", 5),
        ("NuGet", "Acme.Core", "3.0.0", 20),
    ]


PUBSPEC = """# Generated by pub
packages:
  async:
    dependency: transitive
    description:
      name: async
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  mylib:
    dependency: "direct main"
    description:
      path: "../mylib"
      relative: true
    source: path
    version: "0.0.1"
  private_pkg:
    dependency: "direct main"
    description:
      name: private_pkg
      url: "https://pub.example.invalid"
    source: hosted
    version: "1.0.0"
  acme_dart:
    dependency: "direct main"
    description:
      name: acme_dart
      url: "https://pub.dartlang.org"
    source: hosted
    version: "1.4.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"""


def test_pubspec_lock_reads_hosted_pub_dev_packages_only() -> None:
    assert _triples(parse_pubspec_lock(PUBSPEC).dependencies) == [
        ("Pub", "async", "2.11.0", 3),
        ("Pub", "acme_dart", "1.4.0", 25),
    ]


BUN_LOCK = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "left-pad": "^1.3.0",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-abc"],
    "@scope/pkg": ["@scope/pkg@2.0.0", "", { "dependencies": { "x": "1" } }, "sha512-def"],
    "app": ["app@workspace:."],
    "alias": ["alias@npm:real@1.0.0", "", {}, "sha512-x"],
    "gh": ["gh@github:user/repo#abc", "", {}],
  }
}
"""


def test_bun_lock() -> None:
    assert _triples(parse_bun_lock(BUN_LOCK).dependencies) == [
        ("npm", "left-pad", "1.3.0", 12),
        ("npm", "@scope/pkg", "2.0.0", 13),
    ]


def test_dispatch_and_ecosystem_of_each_file() -> None:
    names = {
        "composer.lock": "Packagist",
        "sub/go.mod": "Go",
        "go.sum": "Go",
        "Cargo.lock": "crates.io",
        "app/pom.xml": "Maven",
        "gradle.lockfile": "Maven",
        "Gemfile.lock": "RubyGems",
        "packages.lock.json": "NuGet",
        "pubspec.lock": "Pub",
        "bun.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "uv.lock": "PyPI",
        "requirements-dev.txt": "PyPI",
    }
    for rel, ecosystem in names.items():
        assert parser_for(rel) is not None and ecosystem_for_file(rel) == ecosystem, rel
    assert parser_for("README.md") is None and ecosystem_for_file("README.md") is None
    binary = parser_for("bun.lockb")
    assert binary is not None and "binary" in (binary("").unsupported or "")


# ----- scans against a synthetic index


@pytest.fixture
def project(tmp_path: Path, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    osv.build(isolated_osv_index, ecosystems=osv.ALL)
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def test_composer_lock_pinning_an_affected_library_is_reported(project: Path) -> None:
    """The day-zero case: a PHP library in composer.lock is hit by a new advisory; the scan names it and the fix."""
    (project / "composer.lock").write_text(COMPOSER_LOCK)
    report = scan([project], root=project)
    [finding] = report.findings
    assert (finding.path, finding.line, finding.rule_id) == ("composer.lock", 5, "dep.vulnerable")
    assert finding.severity == "critical" and finding.cwe == "CWE-94"
    assert (
        "acme/php-lib@v2.3.1 (Packagist) has 1 known vulnerability(ies): GHSA-php1-demo-0001 (CVE-2026-0003)"
        in finding.message
    )
    assert "Remote code execution in acme/php-lib" in finding.message and "fixed in 2.3.5" in finding.message
    assert finding.fix == "Upgrade acme/php-lib to 2.3.5 or later and update the lockfile."
    assert [note.id for note in report.notes] == [
        "dep.not_checked"
    ]  # the dev-main branch is listed, not skipped silently
    assert "acme/branchy" in report.notes[0].message
    text = render(report, "text", color=False)
    assert "composer.lock" in text and "CRITICAL  dep.vulnerable  CWE-94" in text
    # The fixed release is clean.
    (project / "composer.lock").write_text(COMPOSER_LOCK.replace("v2.3.1", "v2.3.5"))
    assert not scan([project], root=project).findings


def test_every_added_ecosystem_reports_through_its_lockfile(project: Path) -> None:
    files = {
        "go.mod": "module x\n\nrequire github.com/acme/gomod v1.3.0\n",
        "Cargo.lock": '[[package]]\nname = "acme-crate"\nversion = "0.2.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
        "pom.xml": "<project><dependencies><dependency><groupId>org.acme</groupId><artifactId>acme-core</artifactId><version>1.2.0.RELEASE</version></dependency></dependencies></project>",
        "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    acme_gem (2.0.9)\n",
        "packages.lock.json": json.dumps(
            {"version": 1, "dependencies": {"net8.0": {"acme.core": {"type": "Direct", "resolved": "3.0.0"}}}}, indent=1
        ),
        "pubspec.lock": 'packages:\n  acme_dart:\n    description:\n      url: "https://pub.dev"\n    source: hosted\n    version: "1.4.9"\n',
    }
    for name, text in files.items():
        (project / name).write_text(text)
    report = scan([project], root=project)
    found = {f.path: f for f in report.findings}
    assert set(found) == set(files)
    assert "GO-2026-0001" in found["go.mod"].message and "fixed in 1.4.0" in found["go.mod"].message
    assert "RUSTSEC-2026-0001" in found["Cargo.lock"].message and found["Cargo.lock"].fix.startswith(
        "Upgrade acme-crate to 0.3.2"
    )
    assert "fixed in 1.2.5.RELEASE" in found["pom.xml"].message and "(Maven)" in found["pom.xml"].message
    assert found["Gemfile.lock"].fix.startswith("Upgrade acme_gem to 2.1.0")
    assert (
        "acme.core@3.0.0 (NuGet)" in found["packages.lock.json"].message
    )  # matched although the advisory says Acme.Core
    assert found["pubspec.lock"].severity == "high"


def test_only_ecosystems_in_the_index_are_checked_and_the_gap_is_a_note(
    tmp_path: Path, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    osv.build(isolated_osv_index)  # PyPI and npm only
    root = tmp_path / "p"
    root.mkdir()
    (root / "composer.lock").write_text(COMPOSER_LOCK)
    monkeypatch.chdir(root)
    report = scan([root], root=root)
    assert not report.findings
    [gap] = [n for n in report.notes if n.id == "dep.ecosystem_missing"]
    assert gap.path == "composer.lock" and "db update --ecosystem Packagist" in gap.message


def test_unparseable_versions_are_reported_as_possibly_affected(project: Path) -> None:
    (project / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.acme</groupId><artifactId>acme-core</artifactId>"
        "<version>1.0.0</version></dependency></dependencies></project>"
    )
    (project / "requirements.txt").write_text("demo-pkg==1.0-foo\n")  # not a PEP 440 version
    report = scan([project], root=project)
    found = {f.path: f for f in report.findings}
    legacy = found["requirements.txt"]
    assert legacy.rule_id == "dep.vulnerable" and legacy.confidence == "low"
    assert "demo-pkg@1.0-foo (PyPI) is possibly affected" in legacy.message
    assert "could not be compared exactly" in legacy.message and "fixed in 2.0.1" in legacy.message
    assert "Check demo-pkg 1.0-foo against" in legacy.fix
    assert found["pom.xml"].confidence == "high"  # 1.0.0 is inside [1.0, 1.2.5.RELEASE): a definite match
    assert "possibly" not in found["pom.xml"].message


def test_possible_findings_can_be_ignored_like_any_advisory(project: Path) -> None:
    (project / "requirements.txt").write_text("demo-pkg==1.0-foo\n")
    config = project / ".kestrix.toml"
    config.write_text(
        'ignore-advisories = {"GHSA-aaaa-bbbb-cccc" = "checked by hand", "GHSA-dddd-eeee-ffff" = "same"}\n'
    )
    from kestrix_scan.config import load_file

    report = scan([project], root=project, config=load_file(config))
    assert not report.findings and report.suppressed == 1


def test_needed_ecosystems(tmp_path: Path, isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index)  # PyPI and npm
    project = tmp_path / "project"
    project.mkdir()
    (project / "composer.lock").write_text("{}")
    (project / "app").mkdir()
    (project / "app" / "go.mod").write_text("module x\n")
    assert deps.needed_ecosystems([project]) == [
        "PyPI",
        "npm",
        "Packagist",
        "Go",
    ]  # PyPI and npm are in the index already
    assert deps.needed_ecosystems([project], ("Pub",)) == ["PyPI", "npm", "Packagist", "Go", "Pub"]


def test_large_lockfiles_scan_fast(project: Path) -> None:
    """Bounded work on big lockfiles: 20,000 npm packages, 5,000 Composer packages and 5,000 gems."""
    import time

    packages = {"": {"name": "big"}} | {f"node_modules/pkg-{i}": {"version": f"1.{i % 50}.0"} for i in range(20_000)}
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2))
    composer = {"packages": [{"name": f"vendor/lib-{i}", "version": f"2.{i % 30}.1"} for i in range(5_000)]}
    (project / "composer.lock").write_text(json.dumps(composer, indent=4))
    (project / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        + "".join(f"    gem{i} (1.{i % 40}.0)\n" for i in range(5_000))
    )
    started = time.perf_counter()
    report = scan([project], root=project)
    elapsed = time.perf_counter() - started
    assert report.files_scanned == 3 and not report.findings
    assert elapsed < 10, f"scanning three large lockfiles took {elapsed:.1f} s"
