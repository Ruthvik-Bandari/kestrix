# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Heuristic cues of business email compromise (BEC), phishing and spam offers in the subject and text.

These are small, curated phrase lists, not a language model or a classifier: English for every
family, plus Russian for the gambling and prize offers. They miss paraphrases and other languages,
and ordinary mail can use the same words. Each cue family is reported at most once, with the
matched phrase (at most 60 characters) as evidence. A payment or gift-card request together with
urgency or secrecy is the classic BEC shape and raises one more, high finding. A run of invisible
characters is reported separately. The text scanned is the parser's bounded decoded text; nothing
else is read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .analyzers import _finding
from .models import Finding, Severity
from .parse import ParsedMessage

MAX_CUE_CHARS = 60

_FLAGS = re.IGNORECASE
_NOT = r"(?:n['\u2019]?t| not)"  # don't, dont, do not, and don't with a typographic apostrophe (U+2019)


def _cue(*patterns: str) -> re.Pattern[str]:
    """One case-insensitive regex; spaces in a pattern match any run of whitespace."""
    whitespace = r"\s+"
    return re.compile("|".join(rf"\b(?:{pattern.replace(' ', whitespace)})\b" for pattern in patterns), _FLAGS)


@dataclass(frozen=True)
class _Family:
    name: str
    severity: Severity
    title: str
    explanation: str
    pattern: re.Pattern[str]


_FAMILIES = (
    _Family(
        "payment_change",
        "medium",
        "Asks for a payment or a change of bank details",
        "Fraudsters impersonate suppliers, executives or payroll to redirect a payment. Confirm any new bank "
        "details by phone, using a number you already have, before paying.",
        _cue(
            r"bank(?:ing)? (?:account )?(?:details|information|info) (?:(?:have|has) )?(?:been )?(?:changed|updated)",
            r"(?:changed?|updated?|new) (?:our |the |my )?bank(?:ing)? (?:account|details|information)",
            r"new (?:bank )?account (?:number|details)",
            r"wire transfer",
            r"update (?:your |the |our )?payment",
        ),
    ),
    _Family(
        "gift_cards",
        "medium",
        "Asks for gift cards",
        "Requests to buy gift cards and send the codes are a common scam: the money cannot be traced or "
        "recovered. No real employer, bank or agency asks for payment this way.",
        _cue(
            r"(?:buy|purchase|get|pick up|send me) (?:me |us )?(?:some |a few |the |\d+ )?(?:\w+ )?gift(?: )?cards?",
            r"gift(?: )?card (?:codes?|numbers?|pins?)",
            r"(?:itunes|google play|steam) cards?",
            r"scratch (?:off )?the (?:back|card|code)",
        ),
    ),
    _Family(
        "urgency",
        "low",
        "Pushes you to act urgently",
        "Pressure to act immediately is used to stop you from checking a request. Legitimate senders "
        "rarely need an answer within minutes.",
        _cue(
            r"urgent(?:ly)?",
            r"immediately",
            r"within (?:24|48|twenty-four|forty-eight) hours",
            r"(?:account|mailbox|access) (?:will|may) be (?:suspended|closed|locked|deactivated|terminated|disabled)",
            r"as soon as possible",
            r"final (?:notice|warning)",
        ),
    ),
    _Family(
        "secrecy",
        "low",
        "Asks you to keep it secret",
        "Asking you not to tell colleagues keeps the usual checks from catching a fraudulent request.",
        _cue(
            r"keep (?:this|it) (?:confidential|between us|private|quiet|to yourself)",
            rf"do{_NOT} (?:tell|mention this to|discuss this with) (?:anyone|anybody|others|colleagues)",
            r"(?:be|stay) discreet",
            r"discreetly",
        ),
    ),
    _Family(
        "credential_request",
        "medium",
        "Asks you to sign in or confirm your password",
        "Messages that ask you to verify an account usually link to a fake sign-in page. Go to the site "
        "yourself, from a bookmark, instead of using the link.",
        _cue(
            r"verify your (?:account|identity|email|mailbox|password|login)",
            r"confirm your (?:password|account|credentials|login|identity)",
            r"(?:sign|log)(?:-| )?in to (?:continue|confirm|verify|restore|unlock)",
            r"unusual (?:sign|log)(?:-| )?in",
            r"(?:re-?enter|update) your (?:password|credentials|login details)",
        ),
    ),
    _Family(
        "gambling_offer",
        "medium",
        "Advertises gambling bonuses such as free spins",
        "Unsolicited casino offers (free spins, no-deposit bonuses, deposit doubling) are a common kind of spam. "
        "They are used to sign people up to unlicensed sites that make withdrawals hard or take card details.",
        _cue(
            r"free spins?",
            r"no-?deposit (?:bonus|spins?)",
            r"no deposit (?:bonus|spins?)",
            r"\d+\s?(?-i:FS)",
            r"casino bonus(?:es)?",
            r"фриспин\w*",
            r"бесплатн\w* (?:спин|вращени)\w*",
            r"без депозита",
            r"бонус\w* (?:на|за|к) (?:первый )?депозит\w*",
        ),
    ),
    _Family(
        "prize_claim",
        "medium",
        "Says you have won a prize",
        "Messages that announce a win you did not enter for are a classic scam opening. The next step asks for a "
        "fee, card details or personal data to release the prize.",
        _cue(
            r"you(?:'ve|\u2019ve| have)? won(?!['\u2019]t)",
            r"claim your (?:prize|reward|winnings)",
            r"(?:lottery|sweepstakes) (?:winner|win|prize)",
            r"you(?:'ve|\u2019ve| have) been selected (?:to receive|as (?:a|the|our) winner)",
            r"вы выиграли",
            r"ваш (?:приз|выигрыш)",
            r"(?:получите|заберите) (?:свой |ваш )?(?:приз|выигрыш)",
            r"вы стали победителем",
        ),
    ),
)
_INVOICE = _cue(r"invoice (?:is )?attached", r"attached (?:is )?(?:the |your |an |our )?invoice")
_PAYMENT_FAMILIES = {"payment_change", "gift_cards"}
_PRESSURE_FAMILIES = {"urgency", "secrecy"}
# Zero-width and other invisible characters. Marketing mail pads its preview text with a few; spam
# uses long runs to break up words or hide text from filters.
_INVISIBLE = re.compile("[\u00ad\u034f\u180e\u200b-\u200f\u2060-\u2064\ufeff]")
MIN_INVISIBLE = 20


def analyze_intent(msg: ParsedMessage) -> list[Finding]:
    """Cue families matched in the subject and decoded text. Heuristic and English only."""
    # The subject and each text part are searched separately so a phrase never spans two of them.
    segments = [msg.subject or "", *msg.texts]
    matched: dict[str, str] = {}
    for family in _FAMILIES:
        found = _first_match(family.pattern, segments)
        if found is not None:
            matched[family.name] = found
    if "payment_change" not in matched and "urgency" in matched:
        invoice = _first_match(_INVOICE, segments)
        if invoice is not None:
            matched["payment_change"] = _cue_text(f"{invoice} + {matched['urgency']}")
    findings = [
        _finding(f"mail.intent.{family.name}", family.severity, family.title, family.explanation, matched[family.name])
        for family in _FAMILIES
        if family.name in matched
    ]
    payment = sorted(_PAYMENT_FAMILIES & matched.keys())
    pressure = sorted(_PRESSURE_FAMILIES & matched.keys())
    if payment and pressure:
        findings.append(
            _finding(
                "mail.intent.bec_pattern",
                "high",
                "Payment request combined with pressure or secrecy",
                "The message asks for money or gift cards and also pushes for speed or secrecy. That combination "
                "is the typical shape of business email compromise. Verify the request through another channel.",
                f"{' and '.join(payment)} with {' and '.join(pressure)}",
            )
        )
    hidden = _hidden_text_finding(segments)
    if hidden is not None:
        findings.append(hidden)
    return findings


def _hidden_text_finding(segments: list[str]) -> Finding | None:
    """One finding when the subject and text together hold at least 20 invisible characters."""
    found = [char for segment in segments for char in _INVISIBLE.findall(segment)]
    if len(found) < MIN_INVISIBLE:
        return None
    common = max(set(found), key=found.count)
    return _finding(
        "mail.intent.hidden_text",
        "low",
        "Text is padded with invisible characters",
        "The message contains many zero-width or otherwise invisible characters. Spam uses them to split words "
        "so filters miss them or to hide text; newsletters sometimes use a few to pad their preview line.",
        f"{len(found)} invisible characters, mostly U+{ord(common):04X}",
    )


def _first_match(pattern: re.Pattern[str], segments: list[str]) -> str | None:
    for segment in segments:
        match = pattern.search(segment)
        if match is not None:
            return _cue_text(match.group(0))
    return None


def _cue_text(text: str) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= MAX_CUE_CHARS else compact[: MAX_CUE_CHARS - 1] + "…"
