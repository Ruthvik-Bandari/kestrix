# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules added after the link and file benchmark (round 1); every sample is synthetic and a few bytes long."""

import io
import zipfile

import pytest
from forensics_samples import pe_bytes, random_bytes

from kestrix.forensics.analysis import analyze_file, detect_kind
from kestrix.forensics.models import Finding
from kestrix.forensics.url import analyze_url


def findings(data: bytes, name: str) -> dict[str, Finding]:
    return {f.id: f for f in analyze_file(io.BytesIO(data), name).findings}


def office(part: str, macro: bool, padding: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr(f"{part}/document.xml", b"x" * padding)  # pushes the macro part past the header sample
        if macro:
            zf.writestr(f"{part}/vbaProject.bin", b"\xd0\xcf\x11\xe0 macro")
    return buf.getvalue()


@pytest.mark.parametrize(("name", "severity"), [("a.docm", "medium"), ("a.docx", "high"), ("a.dat", "medium")])
def test_macro_project_in_an_office_package(name: str, severity: str) -> None:
    assert findings(office("word", True), name)["macro_office_file"].severity == severity


def test_macro_part_is_found_in_the_central_directory_beyond_the_header_sample() -> None:
    data = office("word", True, padding=200_000)
    assert b"vbaProject.bin" not in data[:65536]
    assert "macro_office_file" in findings(data, "big.docm")


def test_office_package_without_macros_is_clean() -> None:
    assert "macro_office_file" not in findings(office("word", False), "a.docx")
    assert "macro_office_file" not in findings(office("xl", False), "a.xlsx")


def zip_bytes(encrypted: bool) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"hello")
    data = bytearray(buf.getvalue())
    if encrypted:
        data[6] |= 1  # general purpose flag bit 0 of the first local header
    return bytes(data)


def test_encrypted_zip_flag() -> None:
    assert findings(zip_bytes(True), "a.zip")["encrypted_archive"].severity == "medium"
    assert "encrypted_archive" not in findings(zip_bytes(False), "a.zip")


def test_program_hidden_in_a_document_or_image() -> None:
    pdf = b"%PDF-1.4\n(text)\n" + b"\n" * 64 + pe_bytes(b"x" * 50)
    assert findings(pdf, "a.pdf")["embedded_executable"].severity == "high"
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 100 + pe_bytes()
    assert "embedded_executable" in findings(jpeg, "a.jpg")


@pytest.mark.parametrize(
    ("data", "name"),
    [
        (b"%PDF-1.4\n(text MZ here and PE\x00\x00 there)\n", "a.pdf"),
        (b"%PDF-1.4\n" + b"MZ" + b"\xff" * 100, "b.pdf"),  # an MZ pair whose header does not lead to a PE signature
        (pe_bytes(b"x" * 50), "setup.exe"),  # a program is not a document: its own header is at offset 0
        (b"\xff\xd8\xff\xe0" + random_bytes(5000), "c.jpg"),
    ],
)
def test_no_embedded_executable_without_a_real_pe_header(data: bytes, name: str) -> None:
    assert "embedded_executable" not in findings(data, name)


def test_svg_with_a_script_but_not_plain_svg_or_html() -> None:
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1"/>{}</svg>'
    assert (
        findings(svg.replace(b"{}", b"<script>alert(1)</script>"), "a.svg")["active_content_svg"].severity == "medium"
    )
    assert "active_content_svg" not in findings(svg.replace(b"{}", b""), "x.svg")
    assert "active_content_svg" not in findings(b"<html><script>var a=1</script></html>", "a.html")
    assert "active_content_svg" in findings(svg.replace(b"{}", b'<rect onload="x()"/>'), "a.svg")


@pytest.mark.parametrize(
    ("name", "severity"), [("a.vbs", "medium"), ("a.bat", "medium"), ("a.ps1", "medium"), ("a.js", "low")]
)
def test_script_files_windows_runs(name: str, severity: str) -> None:
    assert findings(b"echo hello\n", name)["runnable_script_file"].severity == severity


def test_other_text_is_not_a_runnable_script() -> None:
    assert "runnable_script_file" not in findings(b"echo hello\n", "a.txt")
    assert "runnable_script_file" not in findings(b"echo hello\n", "a.sh")


def test_legacy_office_and_flash_are_expected_to_look_random() -> None:
    ole2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + random_bytes(30000)
    got = findings(ole2, "a.ppt")
    assert "expected_high_entropy" in got and "high_entropy_file" not in got and "high_entropy_region" not in got
    swf = b"CWS\x09" + random_bytes(30000)
    assert detect_kind(swf).id == "swf"
    got = findings(swf, "a.swf")
    assert "expected_high_entropy" in got and "high_entropy_file" not in got and "extension_mismatch" not in got
    assert detect_kind(b"CWS is a plain text start").id != "swf"


@pytest.mark.parametrize(
    ("url", "finding_id"),
    [
        ("https://someone.weebly.com/", "hosting_platform_subdomain"),
        ("https://x.y.github.io/a", "hosting_platform_subdomain"),
        ("https://abc.duckdns.org/", "hosting_platform_subdomain"),
        ("https://a1b2c3.example.com/", "digits_in_subdomain"),
    ],
)
def test_new_host_signals_fire(url: str, finding_id: str) -> None:
    assert finding_id in {f.id for f in analyze_url(url).findings}


@pytest.mark.parametrize(
    "url", ["https://weebly.com/", "https://www.github.io/", "https://a12.example.com/", "https://github.com/x/y"]
)
def test_new_host_signals_stay_quiet(url: str) -> None:
    assert not {f.id for f in analyze_url(url).findings} & {"hosting_platform_subdomain", "digits_in_subdomain"}


def test_a_platform_page_alone_is_only_a_low_signal() -> None:
    report = analyze_url("https://someone.weebly.com/")
    assert report.level == "low" and report.score == 10
