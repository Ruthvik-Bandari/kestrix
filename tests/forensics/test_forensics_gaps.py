# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Legacy Office macros, obfuscated HTML and Windows Script Host JavaScript; every sample is synthetic."""

import io
import random
import struct

import pytest

from kestrix.forensics.analysis import analyze_file, html_obfuscation_signals
from kestrix.forensics.models import Finding
from kestrix.forensics.ole import parse_ole_directory
from kestrixlinkfilebench.synth import cfb_file, html_doc, html_form_redirect, html_with_inline_image

RNG = random.Random(7)


def findings(data: bytes, name: str) -> dict[str, Finding]:
    return {f.id: f for f in analyze_file(io.BytesIO(data), name).findings}


@pytest.mark.parametrize("name", ["a.doc", "a.xls", "a.dat", "a.docx"])
def test_legacy_macro_project_is_found_under_any_name(name: str) -> None:
    got = findings(cfb_file(RNG, True), name)
    assert got["macro_office_file"].severity == "low"


def test_legacy_file_without_macros_is_clean() -> None:
    got = findings(cfb_file(RNG, False), "a.doc")
    assert "macro_office_file" not in got and "ole_unreadable" not in got


def test_ole_result_lists_names() -> None:
    data = cfb_file(RNG, True)
    result = parse_ole_directory(io.BytesIO(data), len(data))
    assert result.readable and result.has_vba and {"VBA", "_VBA_PROJECT", "Macros"} <= result.names


def test_truncated_or_malformed_compound_file_gives_a_note_and_no_macro_finding() -> None:
    data = cfb_file(RNG, True)
    for broken in (data[:600], data[:512], data[:100]):
        got = findings(broken, "a.doc")
        assert "macro_office_file" not in got
        assert got["ole_unreadable"].severity == "info"


def test_directory_chain_loop_is_refused_without_hanging() -> None:
    data = bytearray(cfb_file(RNG, True))
    struct.pack_into("<I", data, 512 + 4 * 2, 1)  # FAT: sector 2 points back at sector 1 (directory loops)
    result = parse_ole_directory(io.BytesIO(bytes(data)), len(data))
    assert not result.readable and "loops" in result.note


def test_directory_pointing_past_the_end_is_refused() -> None:
    data = bytearray(cfb_file(RNG, True))
    struct.pack_into("<I", data, 0x30, 9000)
    assert not parse_ole_directory(io.BytesIO(bytes(data)), len(data)).readable


def test_bad_sector_size_and_bad_magic() -> None:
    data = bytearray(cfb_file(RNG, False))
    struct.pack_into("<H", data, 0x1E, 20)
    assert parse_ole_directory(io.BytesIO(bytes(data)), len(data)).note == "unsupported sector size"
    assert not parse_ole_directory(io.BytesIO(b"x" * 600), 600).readable


@pytest.mark.parametrize("style", ["atob", "hex", "xescape", "uescape", "fromcharcode", "datascript"])
def test_obfuscated_html_styles(style: str) -> None:
    got = findings(html_doc(RNG, True, style), "a.html")
    assert got["obfuscated_html"].severity == "medium"


def test_two_weak_signals_together_but_not_alone() -> None:
    assert findings(html_form_redirect(RNG), "a.htm")["obfuscated_html"].severity == "medium"
    refresh = b'<html><meta http-equiv="refresh" content="0;url=https://example.org/"></html>'
    assert "obfuscated_html" not in findings(refresh, "a.html")
    form = b'<form action="https://example.org/p"></form><script>document.forms[0].submit()</script>'
    assert "obfuscated_html" not in findings(form, "a.html")


def test_ordinary_pages_are_clean() -> None:
    assert "obfuscated_html" not in findings(html_with_inline_image(RNG), "a.html")
    assert "obfuscated_html" not in findings(html_doc(RNG, False), "a.html")
    assert html_obfuscation_signals("<p>hello</p>") == frozenset()


def test_blob_without_a_decoder_nearby_is_not_flagged() -> None:
    blob = "A" * 400
    far = f"<script>var x='{blob}';</script>" + " " * 2000 + "<script>document.write('a')</script>"
    assert "obfuscated_html" not in findings(far.encode(), "a.html")


def test_html_rule_only_applies_to_web_extensions() -> None:
    assert "obfuscated_html" not in findings(html_doc(RNG, True, "atob"), "a.txt")
    assert "obfuscated_html" in findings(html_doc(RNG, True, "atob"), "a.svg")


def test_html_with_non_utf8_bytes_is_still_checked() -> None:
    data = html_doc(RNG, True, "atob") + b"\xe9\xe8"
    assert "obfuscated_html" in findings(data, "latin.html")


@pytest.mark.parametrize(
    ("text", "severity"),
    [
        (b'var s = new ActiveXObject("WScript.Shell"); s.Run("x");', "medium"),
        (b"WScript.Echo(1)", "medium"),
        (b'var f = new ActiveXObject("Scripting.FileSystemObject");', "medium"),
        (b'eval(unescape("%61%6c%65%72%74"));', "medium"),
        (b"eval(atob(payload));", "medium"),
        (b"function f(){return 1} document.title = 'x';", "low"),
        (b"var el = eval('1+1');", "low"),
    ],
)
def test_js_is_medium_only_for_wsh_style(text: bytes, severity: str) -> None:
    assert findings(text, "a.js")["runnable_script_file"].severity == severity


def test_other_script_extensions_are_unchanged() -> None:
    assert findings(b"echo hi\n", "a.bat")["runnable_script_file"].severity == "medium"
