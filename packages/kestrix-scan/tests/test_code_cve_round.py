# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rule changes from round 1 of the CVE-fix benchmark (docs/benchmarks/cvefixes.md): tar extraction without a filter,
and the extra APIs that unpickle what they read."""

import textwrap

import pytest

from kestrix_scan.python_rules import check_python


def ids(source: str) -> list[str]:
    result = check_python(textwrap.dedent(source), "app.py")
    assert isinstance(result, list), result
    return [hit.rule_id for hit in result]


@pytest.mark.parametrize(
    "body",
    [
        "with tarfile.open(path) as tar:\n        tar.extractall(dest)",
        "tar = tarfile.open(path, 'r:gz')\n    tar.extractall(path=dest)",
        "tarfile.open(path).extractall(dest)",
        "tar = tarfile.TarFile(path)\n    tar.extract('member', dest)",
        "with tarfile.open(path) as tar, open('log') as log:\n        tar.extractall(dest, numeric_owner=True)",
    ],
)
def test_tar_extraction_without_a_filter_is_reported(body: str) -> None:
    assert ids(f"import tarfile\n\ndef unpack(path, dest):\n    {body}\n") == ["py.archive.extract"]


@pytest.mark.parametrize(
    "body",
    [
        "with tarfile.open(path) as tar:\n        tar.extractall(dest, filter='data')",
        "with tarfile.open(path) as tar:\n        tar.extractall(dest, filter=tarfile.tar_filter)",
        "with tarfile.open(path) as tar:\n        tar.extractall(dest, members=[m for m in tar if safe(m)])",
        "with tarfile.open(path) as tar:\n        tar.extractall(dest, [m for m in tar if safe(m)])",
        "with tarfile.open(path) as tar:\n        tar.extract('member', dest, filter='data')",
        "with tarfile.open(path) as tar:\n        tar.getnames()",
    ],
)
def test_filtered_or_checked_tar_extraction_is_not_reported(body: str) -> None:
    assert ids(f"import tarfile\n\ndef unpack(path, dest, safe):\n    {body}\n") == []


def test_extractall_on_other_objects_is_not_reported() -> None:
    zip_source = "import tarfile, zipfile\ndef f(p, d):\n    with zipfile.ZipFile(p) as z:\n        z.extractall(d)\n"
    assert ids(zip_source) == []
    assert ids("import tarfile\ndef f(box, d):\n    box.extractall(d)\n") == []
    assert (
        ids("def f(tar, d):\n    tar.extractall(d)\n") == []
    )  # tarfile is not imported, so nothing is known about tar


def test_a_name_bound_in_an_outer_scope_is_followed() -> None:
    source = """
        import tarfile
        ARCHIVE = tarfile.open('data.tgz')

        def unpack(dest):
            ARCHIVE.extractall(dest)
    """
    assert ids(source) == ["py.archive.extract"]


def test_a_name_that_may_hold_something_else_is_not_reported() -> None:
    source = """
        import tarfile

        def unpack(path, dest, flag):
            tar = tarfile.open(path) if flag else make_box()
            tar.extractall(dest)
    """
    assert ids(source) == []


@pytest.mark.parametrize(
    "line",
    [
        "sock.recv_pyobj()",
        "numpy.load(path, allow_pickle=True)",
        "pandas.read_pickle(path)",
        "jsonpickle.decode(text)",
    ],
)
def test_apis_that_unpickle_are_reported(line: str) -> None:
    module = line.split(".", maxsplit=1)[0]
    source = f"import {module}\n\ndef f(sock, path, text):\n    return {line}\n"
    assert ids(source) == ["py.deserialize.pickle"]


@pytest.mark.parametrize(
    "line",
    ["sock.recv_pyobj(flags)", "numpy.load(path)", "numpy.load(path, allow_pickle=False)", "sock.recv_json()"],
)
def test_the_safe_forms_are_not_reported(line: str) -> None:
    source = f"import numpy\n\ndef f(sock, path, flags):\n    return {line}\n"
    assert ids(source) == []
