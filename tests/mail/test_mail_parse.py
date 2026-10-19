# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from mail_samples import BODY_SENTINEL, message, nested_multipart, zip_bytes

from kestrix.core.errors import Reason, Rejected
from kestrix.mail import parse
from kestrix.mail.parse import MAX_DEPTH, MAX_PARTS, normalize_domain, parse_message

SPOOFED = "p\N{CYRILLIC SMALL LETTER A}ypal.com"


def rejected(raw: bytes) -> Reason:
    with pytest.raises(Rejected) as exc:
        parse_message(raw)
    return exc.value.reason


def test_headers_and_addresses() -> None:
    raw = message(
        sender="=?utf-8?b?UGF5UGFs?= <billing@Example.COM>",
        headers=[("Reply-To", "a@one.example, b@two.example"), ("Return-Path", "<bounce@lists.example>")],
    )
    msg = parse_message(raw)
    assert msg.from_ is not None
    assert (msg.from_.display_name, msg.from_.address, msg.from_.domain) == (
        "PayPal",
        "billing@Example.COM",
        "example.com",
    )
    assert [reply.domain for reply in msg.reply_to] == ["one.example", "two.example"]
    assert msg.return_path is not None and msg.return_path.domain == "lists.example"
    assert msg.subject == "Quarterly update"
    assert msg.message_id == "<1@example.com>"
    assert msg.received_count == 0
    assert len(msg.sha256) == 64


def test_authentication_results_keep_header_order() -> None:
    msg = parse_message(message(auth=("top.example; dmarc=pass", "lower.example; dmarc=fail")))
    assert msg.authentication_results == ("top.example; dmarc=pass", "lower.example; dmarc=fail")


def test_idn_domain_keeps_punycode_and_decodes_for_display() -> None:
    assert normalize_domain("XN--PYPAL-4VE.com.") == ("xn--pypal-4ve.com", SPOOFED)
    assert normalize_domain(SPOOFED) == ("xn--pypal-4ve.com", SPOOFED)


def test_html_links_and_visible_text_skip_script_and_style() -> None:
    html = (
        "<style>.x{color:red}</style><p>Visible words</p>"
        '<a href=" https://example.com/a ">Example <b>site</b></a>'
        "<script>var hidden = 'https://script.example/x'; document.write('SCRIPT-ONLY')</script>"
    )
    msg = parse_message(message(html=html))
    html_links = [link for link in msg.links if link.source == "html"]
    assert [(link.href, link.text) for link in html_links] == [("https://example.com/a", "Example site")]
    joined = " ".join(msg.texts)
    assert "Visible words" in joined
    assert "SCRIPT-ONLY" not in joined
    assert "color:red" not in joined


def test_plain_text_urls_are_extracted_conservatively() -> None:
    msg = parse_message(message(text="See https://example.com/path. Or (http://example.org/x), not www.example.net"))
    assert [(link.href, link.source) for link in msg.links] == [
        ("https://example.com/path", "text"),
        ("http://example.org/x", "text"),
    ]


def test_unknown_charset_and_bad_bytes_are_replaced() -> None:
    raw = (
        b"From: a@example.com\r\nSubject: s\r\nContent-Type: text/plain; charset=x-not-real\r\n\r\n"
        b"caf\xe9 https://example.com/\r\n"
    )
    msg = parse_message(raw)
    assert "caf�" in msg.texts[0]
    assert [link.href for link in msg.links] == ["https://example.com/"]


def test_attachment_metadata_and_zip_listing() -> None:
    data = zip_bytes(["readme.txt", "bin/tool.exe"])
    msg = parse_message(message(attachments=[("../../files.zip", data, "application/zip")]))
    (attachment,) = msg.attachments
    assert attachment.filename == "files.zip"
    assert attachment.content_type == "application/zip"
    assert attachment.size == len(data)
    assert attachment.head == data[:8]
    assert attachment.archive is not None
    assert attachment.archive.members == ("readme.txt", "bin/tool.exe")
    assert attachment.archive.encrypted is False
    assert attachment.archive.incomplete is False


def test_zip_listing_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse, "MAX_ARCHIVE_MEMBERS", 3)
    msg = parse_message(
        message(attachments=[("a.zip", zip_bytes([f"f{i}.txt" for i in range(10)]), "application/zip")])
    )
    archive = msg.attachments[0].archive
    assert archive is not None
    assert archive.members == ("f0.txt", "f1.txt", "f2.txt")
    assert archive.incomplete is True


def test_damaged_zip_is_listed_as_incomplete() -> None:
    msg = parse_message(message(attachments=[("a.zip", b"PK\x03\x04" + b"\x00" * 40, "application/zip")]))
    archive = msg.attachments[0].archive
    assert archive is not None and archive.incomplete is True and archive.members == ()


def test_oversized_message_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    assert rejected(b"x" * (parse.MAX_MESSAGE_BYTES + 1)) is Reason.INPUT_TOO_LARGE
    monkeypatch.setattr(parse, "MAX_MESSAGE_BYTES", 100)
    assert rejected(message()) is Reason.INPUT_TOO_LARGE


def test_too_many_parts_is_rejected() -> None:
    attachments = [(f"f{i}.txt", b"x", "application/octet-stream") for i in range(MAX_PARTS)]
    assert rejected(message(attachments=attachments)) is Reason.INPUT_TOO_LARGE


def test_nesting_at_the_limit_is_accepted_and_deeper_is_rejected() -> None:
    assert parse_message(nested_multipart(MAX_DEPTH)).part_count == MAX_DEPTH + 1
    assert rejected(nested_multipart(MAX_DEPTH + 1)) is Reason.NESTING_TOO_DEEP
    assert rejected(nested_multipart(5000)) is Reason.NESTING_TOO_DEEP


def test_parser_recursion_is_reported_as_too_deep(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_: object, **__: object) -> None:
        raise RecursionError

    monkeypatch.setattr(parse.BytesParser, "parsebytes", explode)
    assert rejected(message()) is Reason.NESTING_TOO_DEEP


def test_too_many_headers_is_rejected() -> None:
    headers = [("X-Filler", str(i)) for i in range(parse.MAX_HEADERS)]
    assert rejected(message(headers=headers)) is Reason.INPUT_TOO_LARGE


def test_overlong_header_is_rejected() -> None:
    raw = b"From: a@example.com\r\nX-Long: " + b"a" * parse.MAX_HEADER_CHARS + b"\r\n\r\nbody\r\n"
    assert rejected(raw) is Reason.INPUT_TOO_LARGE


@pytest.mark.parametrize("raw", [b"", b"\x00\x01\x02 garbage \xff\xfe", b"hello: world\n\nnot mail", b"just text"])
def test_non_messages_are_invalid_input(raw: bytes) -> None:
    assert rejected(raw) is Reason.INVALID_INPUT


def test_text_budget_truncates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse, "MAX_TEXT_CHARS", 20)
    msg = parse_message(message(text=BODY_SENTINEL, html="<p>more</p>"))
    assert msg.text_truncated is True
    assert sum(len(text) for text in msg.texts) <= 20


def test_link_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse, "MAX_LINKS", 3)
    msg = parse_message(message(text=" ".join(f"https://h{i}.example/" for i in range(10))))
    assert len(msg.links) == 3
    assert msg.links_truncated is True


# Pre-parse caps on the raw bytes (the stdlib parser's MIME parameter handling is super-linear)

_PARAMS = b"; ".join(b"a%d*=''x" % i for i in range(1500))[:16000]


def _multipart(*parts: bytes) -> bytes:
    head = (
        b"From: a@mail.example\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
    )
    return head + b"".join(b"--B\r\n" + part + b"\r\n" for part in parts) + b"--B--\r\n"


def test_parameter_bomb_is_rejected_quickly() -> None:
    import time

    part = b"Content-Type: application/octet-stream; " + _PARAMS + b"\r\nContent-Disposition: attachment; " + _PARAMS
    raw = _multipart(*[part + b"\r\n\r\nx"] * 199)
    started = time.perf_counter()
    assert rejected(raw) is Reason.INPUT_TOO_LARGE
    assert time.perf_counter() - started < 1


@pytest.mark.parametrize(
    "raw",
    [
        # Too many parameters in a folded Content-Disposition of a part
        _multipart(b"Content-Disposition: attachment;\r\n " + b";\r\n ".join([b"a=b"] * 51) + b"\r\n\r\nx"),
        # One header block over 64 KiB (each field under the per-field cap)
        message(headers=[(f"X-Fill-{i}", "a" * 8000) for i in range(9)]),
        # The headers of an attached message are checked too
        _multipart(b"Content-Type: message/rfc822\r\n\r\nContent-Type: text/plain; " + _PARAMS + b"\r\n\r\nx"),
        # ... and those after a boundary declared with an RFC 2231 parameter
        b"From: a@mail.example\r\nContent-Type: multipart/mixed; boundary*=''B\r\n\r\n--B\r\nContent-Type: a/b; "
        + _PARAMS
        + b"\r\n\r\nx\r\n--B--\r\n",
        # An mbox "From " line does not hide the message's own headers
        b"From sender@mail.example Mon Oct 19 00:00:00 2026\r\nFrom: a@mail.example\r\nContent-Type: a/b; "
        + _PARAMS
        + b"\r\n\r\nx",
    ],
    ids=["params", "block", "nested-message", "rfc2231-boundary", "mbox"],
)
def test_header_caps_cover_every_block(raw: bytes) -> None:
    assert rejected(raw) is Reason.INPUT_TOO_LARGE


def test_total_header_bytes_are_capped() -> None:
    part = b"Content-Type: text/plain\r\nX-Fill: " + b"a" * 8000 + b"\r\n\r\nx"
    assert rejected(_multipart(*[part] * 140)) is Reason.INPUT_TOO_LARGE


def test_realistic_messages_pass_the_header_caps() -> None:
    dkim = (
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example; s=s1; t=1760000000; h=from:to:subject:date:message-id; bh="
        + "A" * 44
        + "; b="
        + "B" * 344
    )
    received = [
        (
            "Received",
            f"from mx{i}.mail.example (mx{i}.mail.example [192.0.2.{i}]) by mx.mail.example with ESMTPS id {i}; Mon, 19 Oct 2026 10:00:0{i % 10} +0000",
        )
        for i in range(30)
    ]
    arc = [
        ("ARC-Seal", f"i={i}; a=rsa-sha256; t=1760000000; cv=pass; d=mail.example; s=arc; b=" + "C" * 344)
        for i in range(1, 4)
    ]
    top = message(headers=[("DKIM-Signature", dkim), *received, *arc])
    assert parse_message(top).received_count == 30
    filename = b"; ".join(b"filename*%d*=utf-8''%%E2%%82%%AC-report-part-%d" % (i, i) for i in range(8))
    attachment = b"Content-Type: application/pdf; name=report.pdf\r\nContent-Disposition: attachment; " + filename
    attachment += b'; size=1234; creation-date="Mon, 19 Oct 2026 10:00:00 +0000"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK'
    forwarded = b"Content-Type: message/rfc822\r\n\r\nFrom: b@mail.example\r\nSubject: fwd\r\nContent-Type: text/plain; charset=utf-8; format=flowed; delsp=yes\r\n\r\n-- \r\nSignature: me\r\n"
    text = b"Content-Type: text/plain; charset=utf-8\r\n\r\nHello,\r\n-----Original Message-----\r\nFrom: c@mail.example\r\nSent: today\r\n\r\nquoted"
    msg = parse_message(_multipart(text, attachment, forwarded))
    assert msg.part_count == 5
    assert msg.attachments[0].filename is not None and msg.attachments[0].filename.startswith("€-report-part-0")


def test_deeply_nested_header_comments_are_rejected_cleanly() -> None:
    raw = b"From: " + b"(" * 3000 + b"a@b.example" + b")" * 3000 + b"\r\nSubject: x\r\n\r\nhi\r\n"
    assert rejected(raw) is Reason.NESTING_TOO_DEEP
