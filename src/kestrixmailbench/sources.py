# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The public corpora of the email benchmark: where each file lives, how it is read and how it is labelled.

Sizes and SHA-256 are not pinned in code: ``acquire`` records them on the first download (trust on
first use) in ``manifests/``, and every later stage re-verifies against that manifest. TREC 2007 is
not available yet; add it here as another ``Source`` with ``kind="mbox"`` or ``"tar_messages"``.
"""

from __future__ import annotations

from dataclasses import dataclass

NAZARIO = "nazario"
SPAMASSASSIN = "spamassassin"
ENRON = "enron"

KIND_MBOX = "mbox"
KIND_TAR_MESSAGES = "tar_messages"
KIND_ENRON = "enron_maildir_tgz"


@dataclass(frozen=True)
class SourceFile:
    name: str
    url: str
    kind: str
    label: str
    # True when the file is one year's mailbox, so the whole file is one split group.
    single_year: bool = False


@dataclass(frozen=True)
class Document:
    """A licence or readme fetched for the record; never read as messages."""

    name: str
    url: str


@dataclass(frozen=True)
class Source:
    name: str
    title: str
    license_spdx: str
    license_note: str
    attribution: str
    landing_url: str
    files: tuple[SourceFile, ...]
    documents: tuple[Document, ...] = ()


_NAZARIO_BASE = "https://www.monkey.org/~jose/phishing"
_SA_BASE = "https://spamassassin.apache.org/old/publiccorpus"

_NAZARIO_FILES = (
    [SourceFile("20051114.mbox", f"{_NAZARIO_BASE}/20051114.mbox", KIND_MBOX, "phishing", single_year=True)]
    + [SourceFile(f"phishing{n}.mbox", f"{_NAZARIO_BASE}/phishing{n}.mbox", KIND_MBOX, "phishing") for n in range(4)]
    + [SourceFile("private-phishing4.mbox", f"{_NAZARIO_BASE}/private-phishing4.mbox", KIND_MBOX, "phishing")]
    + [
        SourceFile(f"phishing-{year}", f"{_NAZARIO_BASE}/phishing-{year}", KIND_MBOX, "phishing", single_year=True)
        for year in range(2015, 2026)
    ]
)

# 20030228_spam_2 is superseded by 20050311_spam_2 (a misclassified message removed), so it is not fetched.
_SA_FILES = tuple(
    SourceFile(f"{name}.tar.bz2", f"{_SA_BASE}/{name}.tar.bz2", KIND_TAR_MESSAGES, "spam" if "spam" in name else "ham")
    for name in (
        "20021010_easy_ham",
        "20021010_hard_ham",
        "20021010_spam",
        "20030228_easy_ham",
        "20030228_easy_ham_2",
        "20030228_hard_ham",
        "20030228_spam",
        "20050311_spam_2",
    )
)

SOURCES: tuple[Source, ...] = (
    Source(
        name=NAZARIO,
        title="Jose Nazario's phishing corpus (raw mbox files, 2005-2025)",
        license_spdx="CC-BY-4.0",
        license_note=(
            "CC BY 4.0 per the author's README (https://www.monkey.org/~jose/phishing/README.txt): derivative "
            "works allowed, attribution required. Hand-classified from one personal inbox; later mailboxes are "
            "not anonymized, so messages are never copied off the cluster."
        ),
        attribution="Nazario, J. Phishing corpus. https://www.monkey.org/~jose/phishing/ (CC BY 4.0)",
        landing_url=f"{_NAZARIO_BASE}/",
        files=tuple(_NAZARIO_FILES),
        documents=(
            Document("LICENSE.txt", f"{_NAZARIO_BASE}/LICENSE.txt"),
            Document("README.txt", f"{_NAZARIO_BASE}/README.txt"),
        ),
    ),
    Source(
        name=SPAMASSASSIN,
        title="Apache SpamAssassin public mail corpus (ham, easy_ham, hard_ham, spam, spam_2)",
        license_spdx="NOASSERTION",
        license_note=(
            "No license is stated. The corpus readme says copyright for the message text remains with the original "
            "senders and that the messages were made public or sent to the maintainer for this use. Used for "
            "research evaluation and training of the benchmark's weights by the owner's decision; not redistributed."
        ),
        attribution="The Apache SpamAssassin Project, public mail corpus. https://spamassassin.apache.org/old/publiccorpus/",
        landing_url=f"{_SA_BASE}/",
        files=_SA_FILES,
        documents=(Document("readme.html", f"{_SA_BASE}/readme.html"),),
    ),
    Source(
        name=ENRON,
        title="Enron email dataset, May 7 2015 release (CMU)",
        license_spdx="NOASSERTION",
        license_note=(
            "No license is stated. The data are real employees' mail and contain personal information, so only a "
            "seeded sample is used, it stays on the cluster, and no address, subject or body is ever reported. "
            "Used for research evaluation and training by the owner's decision; not redistributed."
        ),
        attribution="Cohen, W. W. Enron email dataset. https://www.cs.cmu.edu/~enron/ (May 7, 2015 release)",
        landing_url="https://www.cs.cmu.edu/~enron/",
        files=(
            SourceFile(
                "enron_mail_20150507.tar.gz",
                "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
                KIND_ENRON,
                "ham",
            ),
        ),
    ),
)

BY_NAME = {source.name: source for source in SOURCES}
