# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Bounded parsing of one RFC 5322 message into the facts the analyzers need.

The stdlib ``email`` package with ``policy.default`` does the MIME work. Every structure an
attacker controls is capped: message size, header count and length, MIME depth and part
count, decoded text, links and archive listings. HTML is tokenized with ``html.parser`` to
collect links and visible text; it is never rendered and scripts are skipped. Attachments
are hashed and their first bytes kept in memory for type sniffing; archives are listed from
their central directory and never extracted.
"""

from __future__ import annotations

import codecs
import hashlib
import re
import struct
from dataclasses import dataclass
from email import policy
from email.errors import MessageError
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Literal

from ..core.errors import Reason, Rejected

MIB = 1024 * 1024
MAX_MESSAGE_BYTES = 25 * MIB
MAX_HEADERS = 500
MAX_HEADER_CHARS = 16 * 1024
# Checked on the raw bytes before the stdlib parser runs, whose MIME parameter handling is
# super-linear: one header block (the message's or a part's) and all of them together, and the
# parameters (";") in one Content-Type or Content-Disposition field.
MAX_HEADER_BLOCK_BYTES = 64 * 1024
MAX_TOTAL_HEADER_BYTES = 1024 * 1024
MAX_MIME_PARAMS = 50
MAX_DEPTH = 10
MAX_PARTS = 200
MAX_TEXT_CHARS = 5 * MIB
MAX_LINKS = 500
MAX_ARCHIVE_MEMBERS = 1000
MAX_HREF_CHARS = 2048
MAX_LINK_TEXT_CHARS = 300
MAX_NAME_CHARS = 255
HEAD_BYTES = 8

# Headers that only a message has; a blob with none of these (and no From) is not a message.
_MESSAGE_HEADERS = ("from", "date", "message-id", "received", "subject", "to", "mime-version")
_SKIPPED_TAGS = frozenset({"script", "style"})
# Conservative: an explicit http(s) scheme, stopping at whitespace, quotes and brackets.
_TEXT_URL = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# The stdlib keeps undecodable header bytes as lone surrogates, which are not valid text in a report.
_SURROGATE = re.compile("[\ud800-\udfff]")
_PARSE_ERRORS = (MessageError, ValueError, TypeError, IndexError, AttributeError, LookupError)
# What the stdlib raises on some malformed header values (for example a NUL in a charset name,
# or a parameter list that ends after "*"); the whole message is then rejected as invalid.
_MALFORMED = (MessageError, ValueError, IndexError, LookupError)
# The stdlib parser's line endings and header-line rule (email.feedparser NLCRE and headerRE).
_EOL = re.compile(rb"\r\n|\r|\n")
_HEADER_LINE = re.compile(rb"From |[\x21-\x39\x3b-\x7e]*:")
# Any line starting with "--" may be a MIME boundary, whatever the declared boundary is; only
# those followed by a header-shaped line start a block worth checking.
_DELIMITER = re.compile(rb"(?:(?<=[\r\n])|^)--[^\r\n]*(?:\r\n|\r|\n)(?=From |[\x21-\x39\x3b-\x7e]*:|[ \t])")
_PARAMETERIZED = frozenset({b"content-type", b"content-disposition"})

LinkSource = Literal["html", "text"]


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str
    # Lower-case ASCII (punycode) form, used for every comparison.
    domain: str
    # IDNA-decoded form for display.
    domain_display: str


@dataclass(frozen=True)
class Link:
    href: str
    text: str
    source: LinkSource


@dataclass(frozen=True)
class Archive:
    encrypted: bool
    members: tuple[str, ...]
    # True when the central directory could not be read in full (zip64, damage or the member cap).
    incomplete: bool


@dataclass(frozen=True)
class Attachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str
    head: bytes
    archive: Archive | None


@dataclass(frozen=True)
class ParsedMessage:
    sha256: str
    from_: Address | None
    reply_to: tuple[Address, ...]
    return_path: Address | None
    sender: Address | None
    subject: str | None
    date: str | None
    message_id: str | None
    authentication_results: tuple[str, ...]
    received_count: int
    texts: tuple[str, ...]
    links: tuple[Link, ...]
    attachments: tuple[Attachment, ...]
    part_count: int
    text_truncated: bool
    links_truncated: bool


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse ``raw`` within the caps above. Raises ``Rejected`` for oversized or non-message input."""
    if len(raw) > MAX_MESSAGE_BYTES:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"message is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
    check_raw_headers(raw)
    try:
        msg = BytesParser(EmailMessage, policy=policy.default).parsebytes(raw)
    except RecursionError:
        raise Rejected(Reason.NESTING_TOO_DEEP, f"MIME nesting is deeper than {MAX_DEPTH} levels") from None
    try:
        return _parsed(raw, msg)
    except RecursionError:
        # Header values are parsed lazily; deeply nested comments exhaust the stdlib's recursion.
        raise Rejected(Reason.NESTING_TOO_DEEP, "a header is nested too deeply to parse") from None
    except _MALFORMED:
        raise Rejected(Reason.INVALID_INPUT, "the message has a malformed header that cannot be parsed") from None


def _parsed(raw: bytes, msg: EmailMessage) -> ParsedMessage:
    if not any(name in msg for name in _MESSAGE_HEADERS):
        raise Rejected(Reason.INVALID_INPUT, "input is not an email message: it has no message headers")
    parts = _walk(msg)
    collector = _Collector()
    for part in parts:
        collector.add(part)
    return ParsedMessage(
        sha256=hashlib.sha256(raw).hexdigest(),
        from_=_first(_addresses(msg, "from")),
        reply_to=_addresses(msg, "reply-to"),
        return_path=_single_address(_header(msg, "return-path")),
        sender=_first(_addresses(msg, "sender")),
        subject=_header(msg, "subject"),
        date=_header(msg, "date"),
        message_id=_header(msg, "message-id"),
        authentication_results=tuple(_all_headers(msg, "authentication-results")),
        received_count=len(msg.get_all("received") or []),
        texts=tuple(collector.texts),
        links=tuple(collector.links[:MAX_LINKS]),
        attachments=tuple(collector.attachments),
        part_count=len(parts),
        text_truncated=collector.text_truncated,
        links_truncated=len(collector.links) > MAX_LINKS,
    )


# e.g. ``Mail.fenholtmor.example.`` and ``mail.fenholtmor.example`` compare equal after this.
def normalize_domain(domain: str) -> tuple[str, str]:
    """Return the lower-case ASCII (punycode) form and the IDNA-decoded display form of a domain."""
    name = domain.strip().strip(".").lower()
    try:
        ascii_form = name.encode("idna").decode("ascii") if not name.isascii() else name
    except UnicodeError:
        ascii_form = name
    labels = []
    for label in ascii_form.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except UnicodeError:
            labels.append(label)
    return ascii_form, ".".join(labels)


def check_raw_headers(raw: bytes) -> None:
    """Bound header sizes and MIME parameter counts on the raw bytes, before the stdlib parses them.

    A header block is the run of header and continuation lines, read as the stdlib parser reads
    it. Blocks are checked at the start of the message, after every line that starts with ``--``
    (a superset of the real MIME boundaries, so a boundary declared in an unusual way cannot hide
    a part's headers), and after a block that declares no type or a ``message/*`` type, whose
    body may itself start with headers (an attached message, or a digest part). Raises
    ``Rejected(INPUT_TOO_LARGE)``.
    """
    total = _check_chain(raw, 0, 0)
    for match in _DELIMITER.finditer(raw):
        total = _check_chain(raw, match.end(), total)


def _check_chain(raw: bytes, pos: int, total: int) -> int:
    """Check the block at ``pos`` and any nested message's block after it; return the header-byte total."""
    while True:
        total, body = _check_block(raw, pos, total)
        if body is None:
            return total
        pos = body


def _check_block(raw: bytes, pos: int, total: int) -> tuple[int, int | None]:
    """Check one header block. Return the running header-byte total and, when the body after the
    block may itself start with headers, the position where that body starts."""
    block = params = 0
    name = ctype = b""
    has_lines = False
    while pos < len(raw):
        eol = _EOL.search(raw, pos)
        end = eol.start() if eol else len(raw)
        line = raw[pos:end]
        if not line:
            nested = has_lines and (not ctype or ctype.lstrip().lower().startswith(b"message/"))
            return total, (eol.end() if nested and eol else None)
        if line[:1] in (b" ", b"\t"):
            params += line.count(b";")
            value = line
        elif _HEADER_LINE.match(line):
            name, _, value = line.partition(b":")
            name = name.strip().lower()
            params = line.count(b";")
        else:
            break
        if name == b"content-type" and len(ctype) < 64:
            ctype += value.strip()
        has_lines = True
        nxt = eol.end() if eol else len(raw)
        block += nxt - pos
        total += nxt - pos
        if block > MAX_HEADER_BLOCK_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"a header block is larger than {MAX_HEADER_BLOCK_BYTES:,} bytes")
        if total > MAX_TOTAL_HEADER_BYTES:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"the headers total more than {MAX_TOTAL_HEADER_BYTES:,} bytes")
        if name in _PARAMETERIZED and params > MAX_MIME_PARAMS:
            raise Rejected(
                Reason.INPUT_TOO_LARGE, f"a {name.decode()} header has more than {MAX_MIME_PARAMS} parameters"
            )
        pos = nxt
    return total, None


def _walk(msg: EmailMessage) -> list[EmailMessage]:
    """Every part, depth-first, with the header, depth and part-count caps enforced."""
    found: list[EmailMessage] = []
    stack: list[tuple[EmailMessage, int]] = [(msg, 0)]
    while stack:
        part, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise Rejected(Reason.NESTING_TOO_DEEP, f"MIME nesting is deeper than {MAX_DEPTH} levels")
        found.append(part)
        if len(found) > MAX_PARTS:
            raise Rejected(Reason.INPUT_TOO_LARGE, f"message has more than {MAX_PARTS} MIME parts")
        _check_headers(part)
        if part.is_multipart():
            children = part.get_payload()
            if isinstance(children, list):
                stack.extend((child, depth + 1) for child in reversed(children) if isinstance(child, EmailMessage))
    return found


def _check_headers(part: EmailMessage) -> None:
    items = list(part.raw_items())
    if len(items) > MAX_HEADERS:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"a part has more than {MAX_HEADERS} header fields")
    for name, value in items:
        if len(name) + len(str(value)) > MAX_HEADER_CHARS:
            raise Rejected(
                Reason.INPUT_TOO_LARGE, f"header {name[:64]!r} is longer than {MAX_HEADER_CHARS:,} characters"
            )


class _Collector:
    """Accumulates text, links and attachments across parts within the text and link budgets."""

    def __init__(self) -> None:
        self.texts: list[str] = []
        self.links: list[Link] = []
        self.attachments: list[Attachment] = []
        self.text_budget = MAX_TEXT_CHARS
        self.text_truncated = False

    def add(self, part: EmailMessage) -> None:
        if part.is_multipart():
            return
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if part.get_content_maintype() == "text" and filename is None and disposition != "attachment":
            subtype = part.get_content_subtype()
            if subtype in {"plain", "html"}:
                self._add_text(part, subtype)
                return
        self.attachments.append(_attachment(part, filename))

    def _add_text(self, part: EmailMessage, subtype: str) -> None:
        if self.text_budget <= 0:
            self.text_truncated = True
            return
        text = _decode_text(part)
        if len(text) > self.text_budget:
            text, self.text_truncated = text[: self.text_budget], True
        self.text_budget -= len(text)
        if subtype == "html":
            html = _HtmlText(MAX_LINKS + 1 - len(self.links))
            html.feed(text)
            html.close()
            self.texts.append(" ".join(html.text))
            self.links.extend(html.links)
        else:
            self.texts.append(text)
            self.links.extend(_text_links(text, MAX_LINKS + 1 - len(self.links)))


class _HtmlText(HTMLParser):
    """Collects visible text and ``<a href>`` links with their inner text. Never renders anything."""

    def __init__(self, link_budget: int) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[Link] = []
        self._link_budget = link_budget
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIPPED_TAGS:
            self._skip_depth += 1
        elif tag == "a":
            self._close_anchor()
            href = next((value for name, value in attrs if name == "href" and value), None)
            self._href = href.strip() if href else None

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data.strip():
            return
        self.text.append(data.strip())
        if self._href is not None:
            self._anchor_text.append(data.strip())

    def close(self) -> None:
        super().close()
        self._close_anchor()

    def _close_anchor(self) -> None:
        if self._href is not None and len(self.links) < self._link_budget:
            text = " ".join(self._anchor_text)[:MAX_LINK_TEXT_CHARS]
            self.links.append(Link(self._href[:MAX_HREF_CHARS], text, "html"))
        self._href, self._anchor_text = None, []


def _text_links(text: str, budget: int) -> list[Link]:
    links: list[Link] = []
    for match in _TEXT_URL.finditer(text):
        if len(links) >= budget:
            break
        url = match.group(0).rstrip(_TRAILING_PUNCTUATION)[:MAX_HREF_CHARS]
        links.append(Link(url, url[:MAX_LINK_TEXT_CHARS], "text"))
    return links


def _decode_text(part: EmailMessage) -> str:
    payload = part.get_payload(decode=True)
    data = payload if isinstance(payload, bytes) else b""
    charset = part.get_content_charset() or "utf-8"
    try:
        codecs.lookup(charset)
    except (LookupError, ValueError):  # unknown, or not a valid name at all (a NUL byte)
        charset = "utf-8"
    return data.decode(charset, errors="replace")


def _attachment(part: EmailMessage, filename: str | None) -> Attachment:
    payload = part.get_payload(decode=True)
    data = payload if isinstance(payload, bytes) else b""
    archive = _zip_listing(data) if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") else None
    return Attachment(
        filename=_clean_name(filename) if filename else None,
        content_type=part.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        head=data[:HEAD_BYTES],
        archive=archive,
    )


def _clean_name(name: str) -> str:
    """Base name only, without control characters, at most 255 characters."""
    base = re.split(r"[\\/]", name)[-1]
    return _text(_CONTROL.sub("", base)).strip()[:MAX_NAME_CHARS]


# ZIP end-of-central-directory and central-directory file header layouts (APPNOTE 4.3.12, 4.3.16).
_EOCD = b"PK\x05\x06"
_EOCD_MIN = 22
_EOCD_SEARCH = _EOCD_MIN + 0xFFFF
_CDH = b"PK\x01\x02"
_CDH_SIZE = 46
_ZIP64_MARKER = 0xFFFFFFFF
_FLAG_ENCRYPTED = 0x1
_FLAG_UTF8 = 0x800


# A listing such as ``hollcroftquill-invoice.zip`` -> member names only; nothing is inflated.
def _zip_listing(data: bytes) -> Archive:
    """Read member names and encryption flags from the central directory. Nothing is decompressed."""
    eocd = data.rfind(_EOCD, max(0, len(data) - _EOCD_SEARCH))
    if eocd < 0 or eocd + _EOCD_MIN > len(data):
        return Archive(encrypted=False, members=(), incomplete=True)
    total, _, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    if cd_offset == _ZIP64_MARKER:
        return Archive(encrypted=False, members=(), incomplete=True)
    members: list[str] = []
    encrypted = False
    offset = cd_offset
    while len(members) < min(total, MAX_ARCHIVE_MEMBERS):
        if offset + _CDH_SIZE > len(data) or data[offset : offset + 4] != _CDH:
            return Archive(encrypted=encrypted, members=tuple(members), incomplete=True)
        flags = struct.unpack_from("<H", data, offset + 8)[0]
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, offset + 28)
        raw_name = data[offset + _CDH_SIZE : offset + _CDH_SIZE + name_len]
        name = raw_name.decode("utf-8" if flags & _FLAG_UTF8 else "cp437", errors="replace")
        members.append(_CONTROL.sub("", name)[:MAX_NAME_CHARS])
        encrypted = encrypted or bool(flags & _FLAG_ENCRYPTED)
        offset += _CDH_SIZE + name_len + extra_len + comment_len
    return Archive(encrypted=encrypted, members=tuple(members), incomplete=total > len(members))


def _header(msg: EmailMessage, name: str) -> str | None:
    try:
        value = msg.get(name)
    except _PARSE_ERRORS:
        return None
    return None if value is None else _text(_CONTROL.sub(" ", str(value))).strip()


def _all_headers(msg: EmailMessage, name: str) -> list[str]:
    try:
        values = msg.get_all(name) or []
    except _PARSE_ERRORS:
        return []
    return [_text(_CONTROL.sub(" ", str(value))).strip() for value in values]


def _addresses(msg: EmailMessage, name: str) -> tuple[Address, ...]:
    try:
        header = msg.get(name)
        found = getattr(header, "addresses", ()) if header is not None else ()
        pairs = [(str(item.display_name), str(item.addr_spec)) for item in found]
    except _PARSE_ERRORS:
        return ()
    return tuple(address for pair in pairs if (address := _address(*pair)) is not None)


def _single_address(value: str | None) -> Address | None:
    if not value:
        return None
    return _address(*parseaddr(value))


def _address(display_name: str, addr_spec: str) -> Address | None:
    addr = _text(addr_spec).strip().strip("<>")
    if "@" not in addr:
        return None
    domain, display = normalize_domain(addr.rsplit("@", 1)[1])
    if not domain:
        return None
    return Address(_text(_CONTROL.sub(" ", display_name)).strip(), addr, domain, display)


def _first(addresses: tuple[Address, ...]) -> Address | None:
    return addresses[0] if addresses else None


def _text(value: str) -> str:
    """``value`` with undecodable bytes (lone surrogates) replaced by U+FFFD."""
    return _SURROGATE.sub("\ufffd", value)
