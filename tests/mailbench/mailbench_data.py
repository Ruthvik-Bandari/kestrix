# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Tiny synthetic corpora for the email benchmark tests: mbox files, a tar of messages and an Enron-style tar.gz.

Nothing here is real mail. ``SENTINEL`` is body text that must never reach a report or a feature row.
"""

import io
import tarfile
from pathlib import Path

from kestrixmailbench.sources import KIND_ENRON, KIND_MBOX, KIND_TAR_MESSAGES, Source, SourceFile

SENTINEL = "ZEBRA-SENTINEL-7Q4 body text that must never appear in any output"


def word(n: int) -> str:
    """A letters-only token unique to ``n`` (digits are masked by the near-duplicate key)."""
    return "".join(chr(97 + int(d)) for d in str(n)) + "qq"


def eml(
    n: int,
    *,
    sender: str = "alice@sender.example",
    subject: str | None = None,
    body: str | None = None,
    date: str = "Mon, 04 Mar 2002 10:00:00 +0000",
    extra: str = "",
) -> bytes:
    subject = subject if subject is not None else f"topic {word(n)}"
    body = body if body is not None else f"{SENTINEL} number {word(n)}"
    return (
        f"From: Alice <{sender}>\nTo: bob@example.org\nSubject: {subject}\nDate: {date}\n"
        f"Message-ID: <{n}@sender.example>\n{extra}\n{body}\n"
    ).encode()


def mbox(messages: list[bytes]) -> bytes:
    out = b""
    for data in messages:
        out += b"From sender@example Mon Mar  4 10:00:00 2002\n" + data + b"\n"
    return out


def tar_of(path: Path, members: dict[str, bytes], mode: str) -> None:
    with tarfile.open(path, mode) as archive:  # type: ignore[call-overload]
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def make_sources(raw: Path) -> tuple[Source, ...]:
    """Three fake sources under ``raw``: phishing mbox files, a ham+spam tar pair and an Enron tar.gz."""
    (raw / "nazario").mkdir(parents=True)
    (raw / "nazario" / "p2005.mbox").write_bytes(
        mbox(
            [
                eml(
                    i,
                    sender="a@evil.example",
                    body=f"{SENTINEL} verify your account {word(i)}",
                    date="Mon, 04 Apr 2005 10:00:00 +0000",
                )
                for i in range(1, 9)
            ]
            + [
                eml(
                    1,
                    sender="a@evil.example",
                    body=f"{SENTINEL} verify your account {word(1)}",
                    date="Mon, 04 Apr 2005 10:00:00 +0000",
                )
            ]
        )
    )
    (raw / "nazario" / "p2006.mbox").write_bytes(
        mbox(
            [
                eml(100 + i, body=f"{SENTINEL} login now {word(i)}", date="Tue, 02 Jan 2006 10:00:00 +0000")
                for i in range(8)
            ]
            + [b"this is not a message at all\n"]
        )
    )
    (raw / "spamassassin").mkdir(parents=True)
    tar_of(
        raw / "spamassassin" / "easy_ham.tar.bz2",
        {f"easy_ham/{i:05d}.abc": eml(200 + i, body=f"{SENTINEL} lunch {word(i)}") for i in range(10)}
        | {"easy_ham/cmds": b"x"},
        "w:bz2",
    )
    tar_of(
        raw / "spamassassin" / "spam.tar.bz2",
        {
            f"spam/{i:05d}.abc": eml(
                300 + i, body=f"{SENTINEL} free spins {word(i)}", date="Mon, 04 Mar 2003 10:00:00 +0000"
            )
            for i in range(10)
        },
        "w:bz2",
    )
    (raw / "enron").mkdir(parents=True)
    tar_of(
        raw / "enron" / "enron.tar.gz",
        {
            f"maildir/user{u}/inbox/{i}.": eml(
                400 + 10 * u + i, body=f"{SENTINEL} meeting {word(10 * u + i)}", date="Tue, 05 Jun 2001 10:00:00 +0000"
            )
            for u in range(3)
            for i in range(10)
        },
        "w:gz",
    )
    return (
        Source(
            "nazario",
            "t",
            "CC-BY-4.0",
            "n",
            "a",
            "u",
            (
                SourceFile("p2005.mbox", "https://x/p", KIND_MBOX, "phishing", single_year=True),
                SourceFile("p2006.mbox", "https://x/q", KIND_MBOX, "phishing"),
            ),
        ),
        Source(
            "spamassassin",
            "t",
            "NOASSERTION",
            "n",
            "a",
            "u",
            (
                SourceFile("easy_ham.tar.bz2", "https://x/h", KIND_TAR_MESSAGES, "ham"),
                SourceFile("spam.tar.bz2", "https://x/s", KIND_TAR_MESSAGES, "spam"),
            ),
        ),
        Source(
            "enron", "t", "NOASSERTION", "n", "a", "u", (SourceFile("enron.tar.gz", "https://x/e", KIND_ENRON, "ham"),)
        ),
    )


def row(
    n: int,
    label: str,
    group: str,
    findings: list[list[str]] | None = None,
    *,
    source: str | None = None,
    year: int | None = 2003,
    split: str = "dev",
    auth: int = 0,
    received: int = 1,
) -> dict[str, object]:
    """A feature row as ``features.run_shard`` writes it, built directly."""
    source = source or {"phishing": "nazario", "spam": "spamassassin", "ham": "spamassassin"}[label]
    return {
        "id": f"id{n:06d}",
        "source": source,
        "subset": "x",
        "label": label,
        "year": year,
        "group": group,
        "split": split,
        "verdict": "clean",
        "score": 0,
        "findings": findings or [],
        "counts": {"parts": 1, "links": 0, "attachments": 0, "text_truncated": False, "links_truncated": False},
        "received": received,
        "auth": auth,
    }


MEDIUM = ["mail.intent.credential_request", "medium", "intent"]
HIGH = ["mail.links.userinfo", "high", "links"]
LOW = ["mail.links.shortener", "low", "links"]
AUTH_FAIL = ["mail.auth.dmarc_fail", "high", "auth"]
AUTH_MISSING = ["mail.auth.missing", "info", "auth"]
