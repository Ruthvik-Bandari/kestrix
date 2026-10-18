"""Synthetic messages and attachments for the mail tests. Nothing here is real mail."""

import io
import zipfile
from collections.abc import Sequence
from email.message import EmailMessage
from email.utils import parseaddr


def pass_all(domain: str = "example.com") -> str:
    return (
        f"mx.example.net; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}"
    )


PASS_ALL = pass_all()
BODY_SENTINEL = "ZEBRA-SENTINEL-7Q4 this sentence is message body and must never appear in a report"


def message(
    *,
    sender: str = "Alice Example <alice@example.com>",
    auth: Sequence[str] | None = None,
    headers: Sequence[tuple[str, str]] = (),
    text: str = f"Hello Bob,\n{BODY_SENTINEL}\n",
    html: str | None = None,
    attachments: Sequence[tuple[str, bytes, str]] = (),
) -> bytes:
    msg = EmailMessage()
    if auth is None:  # all checks pass for the sender's own domain
        auth = (pass_all(parseaddr(sender)[1].rsplit("@", 1)[1]),)
    for value in auth:
        msg["Authentication-Results"] = value
    msg["From"] = sender
    msg["To"] = "bob@example.org"
    msg["Subject"] = "Quarterly update"
    msg["Date"] = "Sat, 17 Oct 2026 10:00:00 +0000"
    msg["Message-ID"] = "<1@example.com>"
    for name, value in headers:
        msg[name] = value
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, data, content_type in attachments:
        maintype, subtype = content_type.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


def zip_bytes(names: Sequence[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"synthetic member")
    return buffer.getvalue()


def mark_encrypted(data: bytes) -> bytes:
    """Set the 'encrypted' flag on every central-directory entry (zipfile cannot write encrypted archives)."""
    out = bytearray(data)
    offset = out.find(b"PK\x01\x02")
    while offset >= 0:
        out[offset + 8] |= 0x01
        offset = out.find(b"PK\x01\x02", offset + 4)
    return bytes(out)


def nested_multipart(depth: int) -> bytes:
    """A message whose MIME tree is ``depth`` multiparts deep."""
    lines = [b"From: alice@example.com", b"Subject: nested", b"MIME-Version: 1.0"]
    for level in range(depth):
        lines += [f'Content-Type: multipart/mixed; boundary="b{level}"'.encode(), b"", f"--b{level}".encode()]
    lines += [b"Content-Type: text/plain", b"", b"innermost"]
    for level in reversed(range(depth)):
        lines.append(f"--b{level}--".encode())
    return b"\r\n".join(lines) + b"\r\n"
