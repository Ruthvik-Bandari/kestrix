# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import io
import sys

import pytest

from kestrix.forensics import exif as exif_module
from kestrix.forensics.analysis import analyze_file
from kestrix.forensics.exif import MAX_TAGS, collect, exif_findings, read_exif

GPS = {1: "N", 2: (40.0, 26.0, 46.0), 3: "W", 4: (79.0, 58.0, 56.0)}
NAMES = {0x010F: "Make", 0x0110: "Model", 0x927C: "MakerNote", 0xA431: "BodySerialNumber"}
GPS_NAMES = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude"}


def jpeg(exif_tags: dict[int, object] | None = None) -> bytes:
    image_module = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image = image_module.new("RGB", (8, 8))
    if exif_tags is None:
        image.save(buffer, "JPEG")
    else:
        exif = image_module.Exif()
        for tag, value in exif_tags.items():
            exif[tag] = value
        image.save(buffer, "JPEG", exif=exif)
    return buffer.getvalue()


def test_collect_names_tags_skips_pointers_and_decodes_gps() -> None:
    data = collect({0x010F: "Cam\x00", 0x8825: 1234}, {0xA431: "SN-1"}, GPS, NAMES, GPS_NAMES)
    assert data is not None
    assert data.tags["Make"] == "Cam"
    assert data.tags["BodySerialNumber"] == "SN-1"
    assert "Tag0x8825" not in data.tags
    assert data.tags["GPSLatitudeRef"] == "N"
    assert data.gps_present
    assert data.gps is not None
    assert data.gps.latitude == pytest.approx(40.446111)
    assert data.gps.longitude == pytest.approx(-79.982222)


def test_collect_summarises_binary_and_unknown_tags() -> None:
    data = collect({0x927C: b"\x01" * 5000, 0x9999: "x" * 500}, {}, {}, NAMES, GPS_NAMES)
    assert data is not None
    assert data.tags["MakerNote"] == "<5000 bytes of binary data>"
    assert len(data.tags["Tag0x9999"]) == exif_module.MAX_VALUE_CHARS
    assert not data.gps_present


def test_collect_caps_tag_count() -> None:
    data = collect({tag: "v" for tag in range(MAX_TAGS + 50)}, {}, {}, {}, {})
    assert data is not None
    assert len(data.tags) == MAX_TAGS
    assert data.tags_truncated


def test_collect_returns_none_without_tags() -> None:
    assert collect({}, {}, {}, NAMES, GPS_NAMES) is None


@pytest.mark.parametrize(
    "gps",
    [
        {1: "N", 2: (40.0, 26.0), 3: "W", 4: (79.0, 58.0, 56.0)},
        {1: "N", 2: (95.0, 0.0, 0.0), 3: "W", 4: (79.0, 58.0, 56.0)},
        {1: "N", 2: (float("nan"), 0.0, 0.0), 3: "W", 4: (79.0, 58.0, 56.0)},
        {1: "N", 2: "garbage", 3: "W"},
    ],
)
def test_invalid_gps_is_present_but_not_decoded(gps: dict[int, object]) -> None:
    data = collect({}, {}, gps, NAMES, GPS_NAMES)
    assert data is not None
    assert data.gps_present
    assert data.gps is None


def test_gps_and_identifying_findings() -> None:
    data = collect({0x010F: "Cam"}, {}, GPS, NAMES, GPS_NAMES)
    assert data is not None
    findings = {finding.id: finding for finding in exif_findings(data)}
    assert findings["gps_location"].severity == "high"
    assert "40.44611" in findings["gps_location"].explanation
    assert "Make" in findings["identifying_metadata"].explanation


def test_no_findings_for_harmless_tags() -> None:
    data = collect({0x0112: "1"}, {}, {}, {0x0112: "Orientation"}, {})
    assert data is not None
    assert exif_findings(data) == []


def test_reads_gps_from_a_real_jpeg() -> None:
    status, data = read_exif(io.BytesIO(jpeg({0x010F: "TestCam", 0x0110: "Model X", 0x8825: GPS})))
    assert status == "ok"
    assert data is not None
    assert data.tags["Make"] == "TestCam"
    assert data.gps is not None
    assert data.gps.latitude == pytest.approx(40.446111)
    assert data.gps.longitude == pytest.approx(-79.982222)


def test_jpeg_without_exif() -> None:
    assert read_exif(io.BytesIO(jpeg())) == ("no_exif", None)


def test_png_without_exif() -> None:
    image_module = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image_module.new("RGB", (4, 4)).save(buffer, "PNG")
    buffer.seek(0)
    assert read_exif(buffer) == ("no_exif", None)


def test_malformed_image_is_unreadable() -> None:
    pytest.importorskip("PIL")
    assert read_exif(io.BytesIO(b"\xff\xd8\xff" + b"\x00" * 64)) == ("unreadable", None)


def test_pixel_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    image_module = pytest.importorskip("PIL.Image")
    data = jpeg()
    monkeypatch.setattr(image_module, "MAX_IMAGE_PIXELS", image_module.MAX_IMAGE_PIXELS)
    monkeypatch.setattr(exif_module, "MAX_IMAGE_PIXELS", 10)
    assert read_exif(io.BytesIO(data)) == ("too_many_pixels", None)


def test_without_pillow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "PIL", None)
    data = b"\xff\xd8\xff\xe0" + b"\x00" * 64
    assert read_exif(io.BytesIO(data)) == ("pillow_not_installed", None)
    report = analyze_file(io.BytesIO(data), "photo.jpg")
    assert report.exif is None
    assert report.exif_status == "pillow_not_installed"


def test_analysis_reports_gps_privacy_finding() -> None:
    data = jpeg({0x010F: "TestCam", 0x8825: GPS})
    report = analyze_file(io.BytesIO(data), "holiday.jpg")
    assert report.exif_status == "ok"
    assert report.exif is not None
    assert report.exif.gps_present
    assert report.findings[0].id == "gps_location"
