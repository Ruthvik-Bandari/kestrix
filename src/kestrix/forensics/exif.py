# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Read-only EXIF extraction through the optional Pillow extra (``kestrix[exif]``).

Only the metadata Pillow parses while opening the file is read; pixel data is never
decoded. Formats are restricted to those that carry EXIF so Pillow does not probe every
plugin against untrusted bytes.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping
from itertools import islice
from typing import Any, BinaryIO

from .models import ExifData, ExifStatus, Finding, GpsPosition

# Pillow refuses images declaring more than twice this many pixels before parsing further,
# which stops pathological dimension headers even though pixels are never decoded here.
MAX_IMAGE_PIXELS = 100_000_000
MAX_TAGS = 200
MAX_VALUE_CHARS = 200
_FORMATS = ("JPEG", "PNG", "TIFF", "WEBP")
_IFD_POINTERS = frozenset({0x8769, 0x8825, 0xA005})  # Exif, GPS and Interop sub-directory offsets
_EXIF_IFD = 0x8769
_GPS_IFD = 0x8825
_IDENTIFYING = (
    "Make",
    "Model",
    "BodySerialNumber",
    "LensSerialNumber",
    "CameraOwnerName",
    "Artist",
    "Software",
    "DateTimeOriginal",
)


def read_exif(stream: BinaryIO) -> tuple[ExifStatus, ExifData | None]:
    """Return the EXIF status and data of an image stream positioned at its start."""
    try:
        from PIL import ExifTags, Image
    except ImportError:
        return "pillow_not_installed", None
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        with Image.open(stream, formats=_FORMATS) as img:
            if img.format == "PNG":
                # PNG's getexif() decodes the whole image to look for a trailing eXIf chunk;
                # use only what the header pass already collected.
                exif = Image.Exif()
                raw = img.info.get("exif")
                if isinstance(raw, bytes):
                    exif.load(raw)
            else:
                exif = img.getexif()
            data = collect(exif, exif.get_ifd(_EXIF_IFD), exif.get_ifd(_GPS_IFD), ExifTags.TAGS, ExifTags.GPSTAGS)
    except Image.DecompressionBombError:
        return "too_many_pixels", None
    except Exception:  # Pillow raises many exception types on malformed input; all mean "unreadable"
        return "unreadable", None
    if data is None:
        return "no_exif", None
    return "ok", data


def collect(
    base: Mapping[int, Any],
    exif_ifd: Mapping[int, Any],
    gps_ifd: Mapping[int, Any],
    names: Mapping[int, str],
    gps_names: Mapping[int, str],
) -> ExifData | None:
    """Flatten the three EXIF directories into named text tags, or None when all are empty."""
    entries = list(islice(_entries(base, exif_ifd, gps_ifd, names, gps_names), MAX_TAGS + 1))
    if not entries:
        return None
    return ExifData(
        tags=dict(entries[:MAX_TAGS]),
        tags_truncated=len(entries) > MAX_TAGS,
        gps_present=bool(gps_ifd),
        gps=_position(gps_ifd),
    )


def exif_findings(data: ExifData) -> list[Finding]:
    findings = []
    if data.gps_present:
        where = f" (about {data.gps.latitude:.5f}, {data.gps.longitude:.5f})" if data.gps else ""
        findings.append(
            Finding(
                id="gps_location",
                severity="high",
                title="Photo contains its GPS location",
                explanation=(
                    f"This image records where it was taken{where}. Anyone who gets the original file can see "
                    "that place, which may be a home or workplace. Remove the metadata (re-export the image or "
                    "use an EXIF remover) before sharing it publicly."
                ),
            )
        )
    identifying = [tag for tag in _IDENTIFYING if tag in data.tags]
    if identifying:
        findings.append(
            Finding(
                id="identifying_metadata",
                severity="low",
                title="Metadata identifies the device, person or time",
                explanation=(
                    f"The image includes {', '.join(identifying)}. These details can link the photo to a specific "
                    "camera or phone, its owner, or when it was taken."
                ),
            )
        )
    return findings


def _entries(
    base: Mapping[int, Any],
    exif_ifd: Mapping[int, Any],
    gps_ifd: Mapping[int, Any],
    names: Mapping[int, str],
    gps_names: Mapping[int, str],
) -> Iterator[tuple[str, str]]:
    for ifd in (base, exif_ifd):
        for tag, value in ifd.items():
            if tag not in _IFD_POINTERS:
                yield names.get(tag, f"Tag0x{tag:04X}"), _render(value)
    for tag, value in gps_ifd.items():
        yield gps_names.get(tag, f"GPSTag0x{tag:04X}"), _render(value)


def _render(value: Any) -> str:
    if isinstance(value, bytes):
        return f"<{len(value)} bytes of binary data>"
    text = str(value).replace("\x00", "").strip()
    return text if len(text) <= MAX_VALUE_CHARS else text[: MAX_VALUE_CHARS - 3] + "..."


def _position(gps: Mapping[int, Any]) -> GpsPosition | None:
    latitude = _degrees(gps.get(2), gps.get(1), 90.0)
    longitude = _degrees(gps.get(4), gps.get(3), 180.0)
    if latitude is None or longitude is None:
        return None
    return GpsPosition(latitude=round(latitude, 6), longitude=round(longitude, 6))


def _degrees(dms: Any, ref: Any, limit: float) -> float | None:
    """Convert an EXIF (degrees, minutes, seconds) triple and N/S/E/W reference to decimal degrees."""
    try:
        degrees, minutes, seconds = (float(part) for part in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    value = degrees + minutes / 60 + seconds / 3600
    if not math.isfinite(value) or not 0 <= value <= limit:
        return None
    return -value if str(ref).strip().upper() in {"S", "W"} else value
