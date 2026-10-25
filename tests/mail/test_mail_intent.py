# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from mail_samples import message

from kestrix.mail import analyze
from kestrix.mail.intent import MAX_CUE_CHARS
from kestrix.mail.models import MailReport


def intent(report: MailReport) -> list[tuple[str, str]]:
    return [(f.id, f.severity) for f in report.findings if f.analyzer == "intent"]


def evidence(report: MailReport, finding_id: str) -> str | None:
    return next(f.evidence for f in report.findings if f.id == finding_id)


# SPF and DKIM pass but no DMARC result: the sender's domain is not proven, so cues keep full weight.
UNPROVEN = ("mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",)


def text_report(text: str, subject: str | None = None) -> MailReport:
    raw = message(text=text, auth=UNPROVEN)
    if subject is not None:
        raw = raw.replace(b"Subject: Quarterly update", f"Subject: {subject}".encode())
    return analyze(raw)


NEWSLETTER = """Hi Bob,

Here is what happened this quarter: we shipped the new reporting view, fixed the export bug and
hired two engineers. Our team update is attached as a PDF, and the full notes are on the blog.

Thanks for reading. You can change your newsletter preferences or unsubscribe at any time.
"""


def test_clean_sample_and_newsletter_do_not_fire() -> None:
    assert intent(analyze(message())) == []
    report = text_report(NEWSLETTER)
    assert intent(report) == []
    assert report.verdict == "clean"


@pytest.mark.parametrize(
    ("text", "finding_id", "severity", "cue"),
    [
        (
            "Please note our bank details have changed.",
            "mail.intent.payment_change",
            "medium",
            "bank details have changed",
        ),
        ("Send it to the new account number below.", "mail.intent.payment_change", "medium", "new account number"),
        ("Can you process a wire transfer today?", "mail.intent.payment_change", "medium", "wire transfer"),
        ("Please update your payment details.", "mail.intent.payment_change", "medium", "update your payment"),
        (
            "Could you buy some Apple gift cards for the team?",
            "mail.intent.gift_cards",
            "medium",
            "buy some Apple gift cards",
        ),
        ("Reply with the gift card codes.", "mail.intent.gift_cards", "medium", "gift card codes"),
        ("Scratch off the back of each card.", "mail.intent.gift_cards", "medium", "Scratch off the back"),
        ("Reply urgently.", "mail.intent.urgency", "low", "urgently"),
        ("Respond within 24 hours.", "mail.intent.urgency", "low", "within 24 hours"),
        ("Please keep this confidential.", "mail.intent.secrecy", "low", "keep this confidential"),
        (
            "Don\N{RIGHT SINGLE QUOTATION MARK}t tell anyone yet.",
            "mail.intent.secrecy",
            "low",
            "Don\N{RIGHT SINGLE QUOTATION MARK}t tell anyone",
        ),
        ("Please be discreet.", "mail.intent.secrecy", "low", "be discreet"),
        ("Verify your account to keep access.", "mail.intent.credential_request", "medium", "Verify your account"),
        ("Confirm your password here.", "mail.intent.credential_request", "medium", "Confirm your password"),
        ("Sign in to continue.", "mail.intent.credential_request", "medium", "Sign in to continue"),
        ("We noticed an unusual sign-in.", "mail.intent.credential_request", "medium", "unusual sign-in"),
    ],
)
def test_single_cue_families(text: str, finding_id: str, severity: str, cue: str) -> None:
    report = text_report(text)
    assert intent(report) == [(finding_id, severity)]
    assert evidence(report, finding_id) == cue


def test_phrases_split_across_lines_and_case_still_match() -> None:
    report = text_report("PLEASE VERIFY\nYOUR   ACCOUNT")
    assert evidence(report, "mail.intent.credential_request") == "VERIFY YOUR ACCOUNT"


def test_each_family_fires_once_with_the_first_match() -> None:
    report = text_report("Urgent. Reply immediately. This is urgent.")
    assert intent(report) == [("mail.intent.urgency", "low")]
    assert evidence(report, "mail.intent.urgency") == "Urgent"


def test_subject_is_searched_but_never_joined_to_the_body() -> None:
    subject = text_report("Thanks for the call.", subject="Urgent: wire transfer")
    assert {finding_id for finding_id, _ in intent(subject)} >= {"mail.intent.payment_change", "mail.intent.urgency"}
    # "update" ends the subject and "bank details" starts the body: no phrase spans the two.
    assert intent(text_report("bank details for the meeting room.", subject="Status update")) == []


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        ("Our bank details have changed. Please pay immediately.", "payment_change with urgency"),
        ("Buy 5 Apple gift cards and keep this confidential.", "gift_cards with secrecy"),
        ("URGENT: buy some gift cards, and be discreet.", "gift_cards with secrecy and urgency"),
    ],
)
def test_payment_with_pressure_is_the_bec_pattern(text: str, pattern: str) -> None:
    report = text_report(text)
    assert ("mail.intent.bec_pattern", "high") in intent(report)
    assert evidence(report, "mail.intent.bec_pattern") == pattern
    assert report.verdict == "malicious"
    assert report.findings[0].id == "mail.intent.bec_pattern"


def test_invoice_attached_with_urgency_counts_as_a_payment_cue() -> None:
    report = text_report("Invoice attached. Please settle it urgently.")
    assert intent(report) == [
        ("mail.intent.bec_pattern", "high"),
        ("mail.intent.payment_change", "medium"),
        ("mail.intent.urgency", "low"),
    ]
    assert evidence(report, "mail.intent.payment_change") == "Invoice attached + urgently"
    assert intent(text_report("Invoice attached for last month.")) == []


def test_credential_request_with_urgency_is_suspicious_not_bec() -> None:
    report = text_report("Unusual sign-in detected. Verify your account within 24 hours.")
    assert intent(report) == [("mail.intent.credential_request", "medium"), ("mail.intent.urgency", "low")]
    assert report.verdict == "suspicious"


def test_cue_evidence_is_compact_and_bounded() -> None:
    report = text_report("Please keep\n\n   this \t confidential.")
    assert evidence(report, "mail.intent.secrecy") == "keep this confidential"
    assert all(len(f.evidence or "") <= MAX_CUE_CHARS for f in report.findings if f.analyzer == "intent")


def test_gift_card_mentions_that_are_not_requests_do_not_fire() -> None:
    assert intent(text_report("Give the perfect present: our gift cards never expire.")) == []


def test_html_text_is_searched_but_scripts_are_not() -> None:
    raw = message(html="<p>Please keep this confidential.</p><script>var a = 'wire transfer';</script>")
    assert intent(analyze(raw)) == [("mail.intent.secrecy", "low")]


ALERT = "We noticed an unusual sign-in. Verify your account."
PROVIDER = frozenset({"mx.example.net"})  # the authserv-id that pass_all() stamps


def test_credential_request_from_a_dmarc_proven_sender_is_low() -> None:
    """A genuine provider alert ("unusual sign-in") must not make its own mail suspicious when the
    DMARC pass comes from the header of a trusted authserv-id."""
    report = analyze(message(text=ALERT), trusted_authserv_ids=PROVIDER)
    assert intent(report) == [("mail.intent.credential_request", "low")]
    assert "trusted authserv-id" in next(f.explanation for f in report.findings if f.analyzer == "intent")
    assert report.verdict == "clean"


def test_an_unverified_dmarc_pass_does_not_lower_a_credential_request() -> None:
    """Without a trusted authserv-id the topmost header could be the sender's own: its pass lowers nothing."""
    report = analyze(message(text=ALERT))
    assert intent(report) == [("mail.intent.credential_request", "medium")]
    assert report.verdict == "suspicious"


def test_a_forged_topmost_header_does_not_clear_a_phishing_message() -> None:
    """The outside-review case: a header naming the attacker's own authserv-id on top of a credential lure."""
    forged = "attacker.invalid; dmarc=pass header.from=example.com"
    raw = message(text=ALERT, auth=(forged,))
    report = analyze(raw)
    assert intent(report) == [("mail.intent.credential_request", "medium")]
    assert report.verdict == "suspicious"
    unverified = next(f for f in report.findings if f.id == "mail.auth.unverified")
    assert unverified.evidence == "topmost header, authserv-id attacker.invalid: dmarc=pass"
    # Also when the forged header sits above the provider's real one and the provider is trusted.
    trusted = analyze(message(text=ALERT, auth=(forged, "mx.example.net; dmarc=none")), trusted_authserv_ids=PROVIDER)
    assert trusted.verdict == "suspicious"


@pytest.mark.parametrize(
    "text",
    [
        "Please validate your online banking login today.",
        "Restore your account before it is locked.",
        "We detected suspicious activity on your account.",
        "Your account has been limited.",
        "Click here to verify your details.",
        "Your mailbox was disabled.",
    ],
)
def test_looser_credential_wording_is_a_credential_request(text: str) -> None:
    assert ("mail.intent.credential_request", "medium") in intent(text_report(text))


def test_an_account_suspension_warning_is_urgent_and_a_credential_request() -> None:
    report = text_report("Your account will be suspended.")
    assert intent(report) == [("mail.intent.credential_request", "medium"), ("mail.intent.urgency", "low")]
    assert evidence(report, "mail.intent.urgency") == "account will be suspended"


@pytest.mark.parametrize(
    "text",
    [
        "Please confirm the meeting time with Dana.",
        "I will update the plan and send the account summary tomorrow.",
        "The password policy document is on the wiki.",
        "Verify the numbers, then confirm with finance.",
        "Confirm the new account number with the supplier.",
    ],
)
def test_ordinary_requests_are_not_credential_requests(text: str) -> None:
    assert [item for item in intent(text_report(text)) if item[0] == "mail.intent.credential_request"] == []
