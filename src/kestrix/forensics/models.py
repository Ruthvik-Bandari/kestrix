"""Response models for file and URL forensics.

Every field carries a plain-language description; it appears in the API docs and is the
reference the dashboard and CLI wording are written against.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]
ExifStatus = Literal["ok", "no_exif", "not_image", "pillow_not_installed", "unreadable", "too_many_pixels"]
UrlLevel = Literal["none", "low", "medium", "high"]

SCORE_NOTE = (
    "Heuristic score from offline checks of the URL text only; the URL was never visited. "
    "It is not a probability of phishing: 0 means none of the checks fired, not that the site is safe."
)


class Finding(BaseModel):
    id: str = Field(description="Stable machine-readable identifier, for example 'extension_mismatch'.")
    severity: Severity = Field(description="Attention it deserves: info (context only), low, medium or high.")
    title: str = Field(description="One-line summary of the finding.")
    explanation: str = Field(description="Plain-language explanation of what was seen and what it may mean.")


_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def by_severity(findings: Iterable[Finding]) -> list[Finding]:
    """Order findings most severe first, keeping the original order within a severity."""
    return sorted(findings, key=lambda finding: _RANK[finding.severity])


class Hashes(BaseModel):
    md5: str = Field(description="MD5 digest; insecure, but still used by older lookup databases.")
    sha1: str = Field(description="SHA-1 digest; insecure, but still common in malware databases.")
    sha256: str = Field(description="SHA-256 digest; the usual fingerprint for looking a file up online.")
    sha512: str = Field(description="SHA-512 digest.")


class FileType(BaseModel):
    id: str = Field(description="Format detected from the content (not the name), e.g. 'pe', 'pdf', 'unknown'.")
    label: str = Field(description="Human-readable name of the detected format.")
    executable: bool = Field(description="True when the content is a program or script that can be run.")
    extension: str | None = Field(description="Extension from the file name, lowercase without the dot.")
    expected_extensions: list[str] = Field(description="Extensions normally used for the detected format.")
    extension_mismatch: bool = Field(
        description="True when the extension does not fit the content, e.g. a program named .pdf."
    )


class EntropyPoint(BaseModel):
    offset: int = Field(description="Byte offset where this point's span of blocks starts.")
    entropy: float = Field(description="Mean entropy of the blocks in this span, in bits per byte (0 to 8).")


class EntropyRegion(BaseModel):
    start: int = Field(description="Byte offset where the random-looking region starts.")
    end: int = Field(description="Byte offset just past the end of the region.")
    mean_entropy: float = Field(description="Mean entropy across the region, in bits per byte.")


class EntropyProfile(BaseModel):
    overall: float = Field(
        description=(
            "Shannon entropy of the whole file in bits per byte: 0 means one repeated byte, "
            "8 means every byte value is equally common, as in encrypted or compressed data."
        )
    )
    block_size: int = Field(description="Size in bytes of each block whose entropy was measured.")
    block_count: int = Field(description="Number of blocks measured.")
    points_span_blocks: int = Field(description="How many consecutive blocks each point in 'points' averages.")
    points: list[EntropyPoint] = Field(description="Entropy across the file, downsampled for charting.")
    high_entropy_threshold: float = Field(description="Block entropy at or above which data counts as random.")
    high_entropy_regions: list[EntropyRegion] = Field(
        description="Runs of random-looking blocks, in file order; capped, see high_entropy_region_count."
    )
    high_entropy_region_count: int = Field(description="Total number of random-looking regions found.")
    high_entropy_bytes: int = Field(description="Total bytes covered by random-looking regions.")


class GpsPosition(BaseModel):
    latitude: float = Field(description="Decimal degrees, negative for south.")
    longitude: float = Field(description="Decimal degrees, negative for west.")


class ExifData(BaseModel):
    tags: dict[str, str] = Field(description="EXIF tag names and values as text; binary values are summarised.")
    tags_truncated: bool = Field(description="True when the image had more tags than are returned.")
    gps_present: bool = Field(description="True when the image has GPS tags that may reveal where it was taken.")
    gps: GpsPosition | None = Field(description="Decoded coordinates, when the GPS tags are complete and valid.")


class FileReport(BaseModel):
    filename: str = Field(description="File name as supplied, without directories or control characters.")
    size: int = Field(description="Size in bytes.")
    hashes: Hashes
    file_type: FileType
    entropy: EntropyProfile
    byte_histogram: list[int] = Field(description="Count of each byte value 0 to 255, in order.")
    printable_ratio: float = Field(
        description="Share of bytes (0 to 1) that are printable ASCII text, tabs or line breaks."
    )
    exif: ExifData | None = Field(description="Image metadata, when it was read; see exif_status.")
    exif_status: ExifStatus = Field(
        description=(
            "ok: metadata returned; no_exif: an image without EXIF; not_image: not a format that carries EXIF; "
            "pillow_not_installed: install kestrix[exif] to read it; unreadable: the metadata is malformed; "
            "too_many_pixels: the image declares implausibly large dimensions, so it was not opened."
        )
    )
    findings: list[Finding] = Field(description="Observations ordered from most to least severe.")


class UrlRequest(BaseModel):
    url: str = Field(description="The URL to check. It is analysed as text and never visited.")


class UrlReport(BaseModel):
    url: str = Field(description="The URL as analysed, with surrounding whitespace removed.")
    scheme: str | None = Field(description="'http' or 'https', or null when the URL was given without one.")
    host: str = Field(description="Host name in its ASCII form; international names appear as punycode (xn--).")
    unicode_host: str = Field(description="Host name as a browser may display it, with punycode decoded.")
    registrable_domain: str | None = Field(
        description="Best offline guess at the domain the owner registered, e.g. example.co.uk; null for IP hosts."
    )
    score: int = Field(ge=0, le=100, description="Heuristic score from 0 to 100; see score_note.")
    level: UrlLevel = Field(description="Band of the score: none (0), low (<30), medium (<60), high (60+).")
    score_note: str = Field(default=SCORE_NOTE, description="How to read the score.")
    findings: list[Finding] = Field(description="Signals that fired, ordered from most to least severe.")
