import hashlib
import io
import math

import pytest
from forensics_samples import docx_head, pe_bytes, random_bytes

from kestrix.core.errors import Reason, Rejected
from kestrix.forensics.analysis import (
    BLOCK_BYTES,
    CHUNK_BYTES,
    MAX_ENTROPY_POINTS,
    MAX_REGIONS,
    analyze_file,
    detect_kind,
    display_name,
    downsample,
    file_extension,
    high_entropy_regions,
    shannon_entropy,
)
from kestrix.forensics.models import FileReport


def analyze(data: bytes, name: str = "sample.bin", **kwargs: int) -> FileReport:
    return analyze_file(io.BytesIO(data), name, **kwargs)


def finding_ids(report: FileReport) -> list[str]:
    return [finding.id for finding in report.findings]


def test_known_hash_vectors() -> None:
    hashes = analyze(b"abc").hashes
    assert hashes.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashes.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hashes.sha512 == (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )


def test_empty_file() -> None:
    report = analyze(b"", "empty.txt")
    assert report.hashes.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert report.size == 0
    assert report.entropy.overall == 0
    assert report.entropy.block_count == 0
    assert report.file_type.id == "empty"
    assert report.printable_ratio == 0
    assert finding_ids(report) == ["empty_file"]


def test_hashes_and_blocks_span_chunk_boundaries() -> None:
    data = random_bytes(2 * CHUNK_BYTES + 12_345)
    report = analyze(data)
    assert report.hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert report.hashes.md5 == hashlib.md5(data).hexdigest()
    assert report.size == len(data)
    assert report.entropy.block_count == math.ceil(len(data) / BLOCK_BYTES)
    assert sum(report.byte_histogram) == len(data)


def test_entropy_of_constant_and_uniform_bytes() -> None:
    assert analyze(b"\x00" * 10_000).entropy.overall == 0
    assert analyze(bytes(range(256)) * 64).entropy.overall == pytest.approx(8.0)
    assert analyze(random_bytes(65_536)).entropy.overall > 7.9


def test_shannon_entropy_of_two_equal_values_is_one_bit() -> None:
    assert shannon_entropy([5, 5], 10) == pytest.approx(1.0)
    assert shannon_entropy([], 0) == 0


def test_block_profile_follows_content() -> None:
    report = analyze(b"\x00" * (4 * BLOCK_BYTES) + random_bytes(4 * BLOCK_BYTES))
    points = report.entropy.points
    assert report.entropy.points_span_blocks == 1
    assert [point.offset for point in points] == [i * BLOCK_BYTES for i in range(8)]
    assert all(point.entropy == 0 for point in points[:4])
    assert all(point.entropy > 7.5 for point in points[4:])


def test_downsample_caps_points() -> None:
    span, means = downsample([1.0] * 1300 + [3.0] * 2)
    assert span == math.ceil(1302 / MAX_ENTROPY_POINTS)
    assert len(means) <= MAX_ENTROPY_POINTS
    assert means[0] == 1.0
    assert downsample([2.0, 4.0]) == (1, [2.0, 4.0])
    assert downsample([2.0, 4.0, 6.0], max_points=2) == (2, [3.0, 6.0])


def test_large_file_is_downsampled_for_charting() -> None:
    report = analyze(b"\x00" * (3 * CHUNK_BYTES))
    assert report.entropy.block_count == 768
    assert report.entropy.points_span_blocks == 2
    assert len(report.entropy.points) == 384
    assert report.entropy.points[1].offset == 2 * BLOCK_BYTES


def test_high_entropy_regions_need_two_blocks() -> None:
    regions = high_entropy_regions([0.0, 8.0, 8.0, 0.0, 8.0], size=5 * BLOCK_BYTES)
    assert [(r.start, r.end, r.mean_entropy) for r in regions] == [(BLOCK_BYTES, 3 * BLOCK_BYTES, 8.0)]


def test_high_entropy_region_ending_at_eof_is_clipped_to_size() -> None:
    regions = high_entropy_regions([8.0, 8.0], size=BLOCK_BYTES + 10)
    assert [(r.start, r.end) for r in regions] == [(0, BLOCK_BYTES + 10)]


def test_returned_regions_are_capped_but_counted() -> None:
    pattern = random_bytes(2 * BLOCK_BYTES) + b"\x00" * BLOCK_BYTES
    report = analyze(pattern * 40)
    assert report.entropy.high_entropy_region_count == 40
    assert len(report.entropy.high_entropy_regions) == MAX_REGIONS
    assert report.entropy.high_entropy_bytes == 40 * 2 * BLOCK_BYTES


@pytest.mark.parametrize(
    ("head", "kind_id"),
    [
        (pe_bytes(), "pe"),
        (b"MZ" + b"\x00" * 100, "dos_mz"),
        (b"\x7fELF\x02\x01\x01", "elf"),
        (b"\xcf\xfa\xed\xfe\x07\x00\x00\x01", "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02", "macho_fat"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "java_class"),
        (b"%PDF-1.7\n", "pdf"),
        (b"junk before header %PDF-1.4\n", "pdf"),
        (b"PK\x03\x04" + b"\x00" * 40, "zip"),
        (docx_head(), "docx"),
        (b"\x89PNG\r\n\x1a\n\x00\x00", "png"),
        (b"\xff\xd8\xff\xe0", "jpeg"),
        (b"GIF89a\x01\x00", "gif"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"),
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
        (b"#!/bin/sh\necho hi\n", "script"),
        (b"plain UTF-8 text, caf\xc3\xa9\n", "text"),
        (random_bytes(512), "unknown"),
        (b"", "empty"),
    ],
)
def test_magic_detection(head: bytes, kind_id: str) -> None:
    assert detect_kind(head).id == kind_id


def test_script_label_names_its_interpreter() -> None:
    assert detect_kind(b"#!/usr/bin/env python3\nprint(1)\n").label == "Script for /usr/bin/env python3"


@pytest.mark.parametrize(
    ("name", "extension"),
    [("photo.JPG", "jpg"), ("archive.tar.gz", "gz"), ("libc.so.6", "so"), ("README", None), (".bashrc", None)],
)
def test_file_extension(name: str, extension: str | None) -> None:
    assert file_extension(name) == extension


def test_program_named_as_document_is_a_high_mismatch() -> None:
    report = analyze(pe_bytes(b"\x00" * 1000), "invoice.pdf")
    assert report.file_type.id == "pe"
    assert report.file_type.executable
    assert report.file_type.extension == "pdf"
    assert report.file_type.extension_mismatch
    mismatch = next(f for f in report.findings if f.id == "extension_mismatch")
    assert mismatch.severity == "high"
    assert report.findings[0].severity == "high"


def test_matching_extension_is_not_flagged() -> None:
    report = analyze(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image.png")
    assert not report.file_type.extension_mismatch
    assert "extension_mismatch" not in finding_ids(report)


def test_text_under_a_binary_extension_is_a_medium_mismatch() -> None:
    report = analyze(b"<html>not really a picture</html>\n", "photo.png")
    assert report.file_type.id == "text"
    mismatch = next(f for f in report.findings if f.id == "extension_mismatch")
    assert mismatch.severity == "medium"


def test_text_and_unknown_content_are_not_mismatched_by_ordinary_names() -> None:
    assert not analyze(b"a,b\n1,2\n", "data.csv").file_type.extension_mismatch
    assert not analyze(random_bytes(100), "blob.dat").file_type.extension_mismatch


def test_versioned_shared_library_is_not_a_mismatch() -> None:
    assert not analyze(b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "libc.so.6").file_type.extension_mismatch


def test_double_extension_lure() -> None:
    report = analyze(pe_bytes(), "invoice.pdf.exe")
    assert "double_extension" in finding_ids(report)
    assert "extension_mismatch" not in finding_ids(report)


def test_right_to_left_override_in_name() -> None:
    right_to_left_override = chr(0x202E)
    report = analyze(pe_bytes(), f"photo{right_to_left_override}gpj.exe")
    assert report.filename == "photogpj.exe"
    assert "bidi_control_in_name" in finding_ids(report)


def test_display_name_drops_directories_and_control_characters() -> None:
    assert display_name("C:\\Users\\me\\evil\x00.txt") == "evil.txt"
    assert display_name("../../etc/passwd") == "passwd"
    assert display_name("") == "upload"


def test_packed_program_is_flagged() -> None:
    report = analyze(pe_bytes(random_bytes(64 * 1024)), "tool.exe")
    assert "possible_packing" in finding_ids(report)
    assert "executable_file" in finding_ids(report)


def test_random_file_without_a_format_looks_encrypted() -> None:
    report = analyze(random_bytes(64 * 1024), "notes.locked")
    assert report.file_type.id == "unknown"
    finding = next(f for f in report.findings if f.id == "high_entropy_file")
    assert finding.severity == "medium"


def test_high_entropy_is_expected_in_compressed_formats() -> None:
    report = analyze(b"PK\x03\x04" + random_bytes(64 * 1024), "bundle.zip")
    assert finding_ids(report) == ["expected_high_entropy"]
    assert report.findings[0].severity == "info"


def test_random_region_inside_ordinary_file() -> None:
    data = b"\x01\x02" * (32 * 1024) + random_bytes(16 * 1024) + b"\x01\x02" * (32 * 1024)
    report = analyze(data, "data.dat")
    assert report.entropy.overall < 7.2
    assert report.entropy.high_entropy_regions[0].start == 64 * 1024
    assert "high_entropy_region" in finding_ids(report)


def test_low_entropy_file_has_no_entropy_findings() -> None:
    report = analyze(b"hello world\n" * 1000, "notes.txt")
    assert report.findings == []
    assert report.printable_ratio == 1.0
    assert report.byte_histogram[ord("l")] == 3000


def test_size_limit() -> None:
    assert analyze(b"x" * 100, max_bytes=100).size == 100
    with pytest.raises(Rejected) as excinfo:
        analyze(b"x" * 101, max_bytes=100)
    assert excinfo.value.reason is Reason.INPUT_TOO_LARGE


def test_non_image_skips_exif() -> None:
    report = analyze(b"plain\n", "a.txt")
    assert report.exif is None
    assert report.exif_status == "not_image"
