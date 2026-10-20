# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""PEP 440 and SemVer ordering, and OSV range matching."""

import pytest

from kestrix_scan.versions import (
    all_versions,
    fixed_versions,
    highest,
    in_range,
    is_affected,
    next_fixed,
    pep440_key,
    semver_key,
    version_key,
)

# Each list is in strictly increasing PEP 440 order (the examples of the specification's ordering section).
PEP440_ORDER = [
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
    "2!0.1",
]


def test_pep440_orders_like_the_specification() -> None:
    keys = [pep440_key(v) for v in PEP440_ORDER]
    assert all(key is not None for key in keys)
    assert keys == sorted(keys)  # type: ignore[type-var]
    assert len(set(keys)) == len(keys)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1.0", "1.0.0"),
        ("1.0", "v1.0"),
        ("1.0a1", "1.0alpha1"),
        ("1.0b2", "1.0-beta.2"),
        ("1.0rc1", "1.0c1"),
        ("1.0rc1", "1.0pre1"),
        ("1.0rc1", "1.0preview1"),
        ("1.0.post1", "1.0-1"),
        ("1.0.post1", "1.0-r1"),
        ("1.0.post0", "1.0.post"),
        ("1.0.dev0", "1.0.dev"),
        ("1.0a0", "1.0a"),
        ("1.0+Ubuntu-1", "1.0+ubuntu.1"),
        ("0!1.0", "1.0"),
        ("1.0RC1", "1.0rc1"),
    ],
)
def test_pep440_normalizes_spellings(left: str, right: str) -> None:
    assert pep440_key(left) == pep440_key(right) is not None


@pytest.mark.parametrize("text", ["", "1.0+", "latest", "1..0", "1.0.0-alpha+", "dev"])
def test_pep440_rejects_non_versions(text: str) -> None:
    assert pep440_key(text) is None


def test_epoch_outranks_release() -> None:
    assert pep440_key("1!0.1") > pep440_key("2024.10")  # type: ignore[operator]


SEMVER_ORDER = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
    "1.2.0",
    "1.10.0",
    "2.0.0",
]


def test_semver_orders_like_the_specification() -> None:
    keys = [semver_key(v) for v in SEMVER_ORDER]
    assert keys == sorted(keys)  # type: ignore[type-var]
    assert len(set(keys)) == len(keys)


def test_semver_ignores_build_metadata_and_accepts_short_forms() -> None:
    assert semver_key("1.0.0+build.5") == semver_key("1.0.0") == semver_key("v1.0.0") == semver_key("1.0")
    assert semver_key("1") == semver_key("1.0.0")
    assert semver_key("01.0.0") is None and semver_key("latest") is None


def _ranges(*events: dict[str, str], kind: str = "ECOSYSTEM") -> list[dict[str, object]]:
    return [{"type": kind, "events": list(events)}]


def test_introduced_and_fixed() -> None:
    ranges = _ranges({"introduced": "1.2"}, {"fixed": "1.4.1"})
    assert not is_affected("PyPI", "1.1.9", ranges, [])
    assert is_affected("PyPI", "1.2", ranges, [])
    assert is_affected("PyPI", "1.4.1rc1", ranges, [])  # a pre-release of the fix is still affected
    assert is_affected("PyPI", "1.4.1.dev0", ranges, [])
    assert not is_affected("PyPI", "1.4.1", ranges, [])
    assert not is_affected("PyPI", "1.4.1.post1", ranges, [])


def test_introduced_zero_means_from_the_start() -> None:
    ranges = _ranges({"introduced": "0"}, {"fixed": "2.0"})
    assert is_affected("PyPI", "0.0.1.dev1", ranges, [])
    assert is_affected("PyPI", "1!0.1", [], []) is False
    assert not is_affected("PyPI", "1!0.1", ranges, [])  # a later epoch is above 2.0


def test_last_affected_includes_that_version() -> None:
    ranges = _ranges({"introduced": "0"}, {"last_affected": "2.1.0"}, kind="SEMVER")
    assert is_affected("npm", "2.1.0", ranges, [])
    assert is_affected("npm", "2.1.0-rc.1", ranges, [])
    assert not is_affected("npm", "2.1.1-alpha", ranges, [])
    assert not is_affected("npm", "2.1.1", ranges, [])


def test_several_intervals_in_unsorted_events() -> None:
    ranges = _ranges({"fixed": "1.26.19"}, {"introduced": "2.0.0"}, {"introduced": "0"}, {"fixed": "2.2.2"})
    assert is_affected("PyPI", "1.26.18", ranges, [])
    assert not is_affected("PyPI", "1.26.19", ranges, [])
    assert is_affected("PyPI", "2.0.0", ranges, [])
    assert not is_affected("PyPI", "2.2.2", ranges, [])
    assert next_fixed("PyPI", "1.26.0", fixed_versions(ranges)) == "1.26.19"
    assert next_fixed("PyPI", "2.1", fixed_versions(ranges)) == "2.2.2"
    assert next_fixed("PyPI", "3.0", fixed_versions(ranges)) is None


def test_explicit_versions_list_matches_normalized_spellings() -> None:
    assert is_affected("PyPI", "1.0.0", [], ["1.0"])
    assert is_affected("PyPI", "legacy-1", [], ["legacy-1"])  # not PEP 440, but listed verbatim
    assert not is_affected("PyPI", "1.0.1", [], ["1.0"])
    assert is_affected("npm", "1.0.0", [], ["1.0.0"])


def test_git_ranges_unknown_ecosystems_and_bad_events_are_ignored() -> None:
    assert not is_affected("PyPI", "1.0", _ranges({"introduced": "0"}, kind="GIT"), [])
    assert not is_affected("Maven", "1.0", _ranges({"introduced": "0"}), [])
    assert in_range(pep440_key("1.0") or (), [{"introduced": "not a version"}], pep440_key) is None
    assert not is_affected("PyPI", "1.0", _ranges({"introduced": "nonsense"}), [])


def test_unparseable_dependency_version_only_matches_listed_versions() -> None:
    assert not is_affected("PyPI", "not-a-version", _ranges({"introduced": "0"}), [])


def test_all_versions_detects_open_ended_ranges() -> None:
    assert all_versions(_ranges({"introduced": "0"}), [])
    assert not all_versions(_ranges({"introduced": "0"}, {"fixed": "1.0"}), [])
    assert not all_versions(_ranges({"introduced": "1.0"}), [])
    assert not all_versions([], ["1.0"])


def test_highest_and_version_key() -> None:
    assert highest("npm", ["1.2.0", "1.10.0", "1.9.9", "junk"]) == "1.10.0"
    assert highest("PyPI", []) is None
    assert version_key("PyPI", "junk") == () < version_key("PyPI", "0")
