# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Russian sample text is meant to contain Cyrillic letters
"""Synthetic messages for patterns the public corpora lack, reported as their own source.

Every message is generated from templates with a seeded generator; none is real mail. The families
mirror the shapes the analyzers document (Russian casino spam with generated hosts and an outdated
mailer, prize scams, gift-card and payment-change BEC, link and attachment tricks) next to ordinary
business mail. A family is the split group, so one template never spans dev and test. Synthetic
messages are never used to learn weights.
"""

from __future__ import annotations

import io
import random
import zipfile
from email.message import EmailMessage

ZWNJ = "‌"
FAMILIES = (
    ("ham_business", "ham"),
    ("ham_newsletter", "ham"),
    ("ham_invite", "ham"),
    ("ham_personal", "ham"),
    ("spam_casino_ru", "spam"),
    ("spam_prize_en", "spam"),
    ("phish_bec_gift_cards", "phishing"),
    ("phish_bec_payment_change", "phishing"),
    ("phish_href_mismatch", "phishing"),
    ("phish_display_spoof", "phishing"),
    ("phish_ip_link", "phishing"),
    ("phish_double_extension", "phishing"),
    ("phish_userinfo_link", "phishing"),
)
_NAMES = ["Alice", "Bruno", "Chen", "Dara", "Elif", "Farid", "Gita", "Hugo", "Ines", "Jonas", "Kira", "Luca"]
_THINGS = ["budget", "roadmap", "hiring plan", "audit notes", "release checklist", "travel policy", "vendor review"]
_SHOPS = ["garden", "books", "bikes", "coffee", "tools", "paper", "plants", "audio"]


def _pass_all(domain: str) -> str:
    return (
        f"mx.example.net; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}"
    )


def _build(
    sender: str,
    subject: str,
    text: str,
    *,
    html: str | None = None,
    auth: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    attachment: tuple[str, bytes] | None = None,
    serial: int,
) -> bytes:
    msg = EmailMessage()
    if auth:
        msg["Authentication-Results"] = auth
    msg["From"] = sender
    msg["To"] = f"user{serial}@example.org"
    msg["Subject"] = subject
    msg["Date"] = "Sat, 17 Oct 2026 10:00:00 +0000"
    msg["Message-ID"] = f"<synthetic-{serial}@example.invalid>"
    for name, value in headers:
        msg[name] = value
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    if attachment is not None:
        msg.add_attachment(attachment[1], maintype="application", subtype="octet-stream", filename=attachment[0])
    for depth, part in enumerate(p for p in msg.walk() if p.is_multipart()):
        part.set_boundary(f"=_kestrix_{serial:06d}_{depth}")  # the stdlib's random boundaries would break determinism
    return msg.as_bytes()


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(zipfile.ZipInfo("note.txt", date_time=(2026, 1, 1, 0, 0, 0)), b"synthetic member")
    return buffer.getvalue()


def _word(rng: random.Random, n: int = 3) -> str:
    return "".join(rng.choice("bcdfgklmnprstvz") + rng.choice("aeiou") for _ in range(n))


def _one(family: str, rng: random.Random, i: int) -> bytes:
    who, thing, shop = rng.choice(_NAMES), rng.choice(_THINGS), rng.choice(_SHOPS)
    word, other = _word(rng, 4), _word(rng, 5)
    domain = f"{word}.example"
    if family == "ham_business":
        return _build(
            f"{who} Example <{who.lower()}@{domain}>",
            f"{thing} for {other}",
            f"Hi,\n\nattached are my notes on the {thing}. Can we talk about {other} on Thursday?\n\nThanks, {who}\n",
            auth=_pass_all(domain),
            serial=i,
        )
    if family == "ham_newsletter":
        html = f'<p>This week in {shop}: {other}</p><a href="https://www.{shop}-{word}.example/week">Read more</a>'
        return _build(
            f"{shop.title()} News <news@{shop}-{word}.example>",
            f"{shop.title()} weekly {other}",
            f"This week in {shop}: {other}\nhttps://www.{shop}-{word}.example/week\n",
            html=html,
            auth=_pass_all(f"{shop}-{word}.example"),
            serial=i,
        )
    if family == "ham_invite":
        return _build(
            f"{who} Example <{who.lower()}@{domain}>",
            f"Invitation: {thing} sync",
            f"You are invited to the {thing} sync about {other}. Room {rng.randint(1, 40)}, 10:30.\n",
            auth=_pass_all(domain),
            serial=i,
        )
    if family == "ham_personal":
        return _build(
            f"{who} <{who.lower()}@{domain}>",
            f"dinner and {other}",
            f"Are you free on Friday? I found a place near the {shop} market that does {other}.\n",
            auth=_pass_all(domain),
            serial=i,
        )
    if family == "spam_casino_ru":
        host1, host2 = f"{_word(rng, 2)}{rng.randint(1, 9)}{_word(rng, 3)}{rng.randint(1, 9)}", _word(rng, 6)
        html = (
            f"<p>До {rng.choice([100, 150, 200])} FS и кэшбэк каждую неделю {other}" + ZWNJ * 40 + "</p>"
            f'<a href="http://{host1}.{domain}/r?t={i}">Открыть набор</a>'
            f'<a href="http://{host2}.{domain}/u">Отписаться</a>'
        )
        return _build(
            f"Менеджер <promo@{domain}>",
            f"Бонус {other}",
            f"Бесплатные спины и бонус на депозит {other}\n",
            html=html,
            auth=_pass_all(domain),
            headers=(("X-Mailer", "Microsoft Outlook Express 6.00.2900.5931"),),
            serial=i,
        )
    if family == "spam_prize_en":
        return _build(
            f"Prize Desk <desk@{domain}>",
            f"Congratulations {who}",
            f"Congratulations, you have won a {thing} voucher. Claim your prize at http://bit.ly/{other}{i}\n",
            serial=i,
        )
    if family == "phish_bec_gift_cards":
        return _build(
            f"{who} Example <{who.lower()}.ceo@{domain}>",
            f"quick favor {other}",
            f"I need you to buy some gift cards for clients today, it is urgent. Keep this confidential, {who}.\n",
            serial=i,
        )
    if family == "phish_bec_payment_change":
        return _build(
            f"Accounts <accounts@{domain}>",
            f"invoice {other}",
            f"Our bank details have changed. Please update your payment before Friday, it is urgent. Ref {other}.\n",
            headers=(("Reply-To", f"accounts@{other}.example"),),
            serial=i,
        )
    if family == "phish_href_mismatch":
        html = f'<p>Verify your account {other}</p><a href="http://{other}-{word}.example/login">www.{word}bank.com</a>'
        return _build(
            f"Security <alert@{domain}>",
            f"Action needed {other}",
            f"Verify your account {other}\n",
            html=html,
            serial=i,
        )
    if family == "phish_display_spoof":
        return _build(
            f'"support@{word}bank.com" <mail@{other}.example>',
            f"Notice {other}",
            f"Please confirm your password to keep your account active. Case {other}.\n",
            serial=i,
        )
    if family == "phish_ip_link":
        html = f'<p>Unusual sign-in {other}</p><a href="http://203.0.113.{rng.randint(1, 250)}/signin">Sign in to continue</a>'
        return _build(
            f"Service <service@{domain}>",
            f"Unusual sign-in {other}",
            f"Sign in to continue {other}\n",
            html=html,
            serial=i,
        )
    if family == "phish_double_extension":
        return _build(
            f"Billing <billing@{domain}>",
            f"Statement {other}",
            f"Your statement {other} is attached.\n",
            attachment=(f"statement-{other}.pdf.exe", _zip()),
            serial=i,
        )
    if family == "phish_userinfo_link":
        html = f'<p>Review {other}</p><a href="https://{word}bank.com@{other}-login.example/p">Review now</a>'
        return _build(f"Review <review@{domain}>", f"Review {other}", f"Review {other}\n", html=html, serial=i)
    raise ValueError(f"unknown family {family}")


def generate(seed: str, per_family: int = 30) -> list[tuple[str, str, bytes]]:
    """(family, label, raw message) for every family, ``per_family`` messages each, in a fixed order."""
    rng = random.Random(seed)
    return [
        (family, label, _one(family, rng, serial))
        for serial, (family, label) in enumerate(f for f in FAMILIES for _ in range(per_family))
    ]
