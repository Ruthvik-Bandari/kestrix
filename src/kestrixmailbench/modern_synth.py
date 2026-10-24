# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Synthetic modern transactional and newsletter mail, a separate labelled cohort (never pooled with real mail).

Every sender is a ``.example`` domain. The headers imitate what 2025 mail from a mail service provider looks like:
DKIM signed by the provider's domain, a bounce address on the provider's domain, ``List-Unsubscribe`` with the
one-click ``List-Unsubscribe-Post``, ``Precedence: bulk``, an ``Authentication-Results`` from the receiving provider,
an ARC set, HTTPS click-tracking links with opaque tokens and a tracking pixel. The generator was written after
reading the dev false-alarm causes, so the cohort tests those shapes; it is a regression set, not an estimate of
real mail.
"""

from __future__ import annotations

import random
from email.message import EmailMessage

FAMILIES = (
    "receipt",
    "password_reset",
    "shipping",
    "newsletter_esp",
    "security_alert",
    "calendar_invite",
    "bank_statement",
    "code_notification",
)
_BRANDS = ["northwind", "contoso", "fabrikam", "tailspin", "wingtip", "adatum", "litware", "proseware"]
_WORDS = ["spring", "autumn", "weekly", "digest", "update", "offer", "summary", "report"]


def _token(rng: random.Random, n: int = 48) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789-_") for _ in range(n))


def _auth(dkim_domain: str, from_domain: str, bounce_domain: str, result: str = "pass") -> str:
    return (
        f"mx.example.net; dkim={result} header.d={dkim_domain} header.s=s1; "
        f"spf={result} smtp.mailfrom={bounce_domain}; dmarc={result} header.from={from_domain}"
    )


def _msg(
    sender: str,
    subject: str,
    text: str,
    html: str,
    *,
    serial: int,
    auth: str,
    bounce: str,
    bulk: bool,
    unsubscribe: str | None = None,
    reply_to: str | None = None,
    extra: tuple[tuple[str, str], ...] = (),
) -> bytes:
    msg = EmailMessage()
    msg["Return-Path"] = f"<{bounce}>"
    msg["Authentication-Results"] = auth
    msg["ARC-Authentication-Results"] = "i=1; mx.example.net; dkim=pass; spf=pass; dmarc=pass"
    msg["ARC-Seal"] = "i=1; a=rsa-sha256; t=1760000000; cv=none; d=example.net; s=arc; b=AAAA"
    msg["ARC-Message-Signature"] = (
        "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.net; s=arc; h=from:to; bh=AAAA; b=BBBB"
    )
    msg["Received"] = (
        "from mta1.example.net (mta1.example.net [192.0.2.10]) by mx.example.net with ESMTPS; Fri, 17 Oct 2026 10:00:01 +0000"
    )
    msg["From"] = sender
    msg["To"] = f"user{serial}@example.org"
    msg["Subject"] = subject
    msg["Date"] = "Fri, 17 Oct 2026 10:00:00 +0000"
    msg["Message-ID"] = f"<synthetic-modern-{serial}@example.invalid>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if bulk:
        msg["Precedence"] = "bulk"
    if unsubscribe:
        msg["List-Unsubscribe"] = f"<{unsubscribe}>, <mailto:unsubscribe@{bounce.split('@')[1]}?subject=unsub>"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    for k, v in extra:
        msg[k] = v
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    for depth, part in enumerate(p for p in msg.walk() if p.is_multipart()):
        part.set_boundary(f"=_kestrix_m_{serial:06d}_{depth}")
    return msg.as_bytes()


def _one(family: str, rng: random.Random, serial: int) -> bytes:
    brand = rng.choice(_BRANDS)
    word = rng.choice(_WORDS)
    domain = f"{brand}.example"
    esp = f"mail-{rng.choice(['sendly', 'postal', 'bulkr'])}.example"
    bounce = f"bounce-{_token(rng, 10)}@{esp}"
    track = f"https://click.{esp}/ls/click?upn={_token(rng, 80)}"
    pixel = f'<img src="https://open.{esp}/o/{_token(rng, 20)}.gif" width="1" height="1" alt="">'
    ref = f"{rng.randint(100000, 999999)}"
    if family == "receipt":
        return _msg(
            f"{brand.title()} Orders <orders@{domain}>",
            f"Your receipt from {brand.title()} #{ref}",
            f"Thanks for your order #{ref}. View your receipt: {track}\n",
            f'<p>Thanks for your order #{ref}.</p><a href="{track}">View receipt</a>{pixel}',
            serial=serial,
            auth=_auth(esp, domain, esp),
            bounce=bounce,
            bulk=False,
        )
    if family == "password_reset":
        return _msg(
            f"{brand.title()} Security <no-reply@{domain}>",
            f"Reset your {brand.title()} password",
            f"Use this link to reset your password within 30 minutes: https://account.{domain}/reset?token={_token(rng)}\n",
            f'<p>Reset your password</p><a href="https://account.{domain}/reset?token={_token(rng)}">Reset password</a>',
            serial=serial,
            auth=_auth(domain, domain, domain),
            bounce=f"no-reply@{domain}",
            bulk=False,
        )
    if family == "shipping":
        return _msg(
            f"{brand.title()} Shipping <shipping@{domain}>",
            f"Your order #{ref} has shipped",
            f"Your package is on its way. Track it: {track}\n",
            f'<p>Your package is on its way.</p><a href="{track}">Track package</a>{pixel}',
            serial=serial,
            auth=_auth(esp, domain, esp),
            bounce=bounce,
            bulk=False,
            extra=(("Feedback-ID", f"{ref}:{brand}:shipping:{esp}"),),
        )
    if family == "newsletter_esp":
        return _msg(
            f"{brand.title()} News <news@{domain}>",
            f"{brand.title()} {word}: what is new",
            f"What is new this {word}. Read more: {track}\nUnsubscribe: {track}\n",
            f'<p>What is new this {word}.</p><a href="{track}">Read more</a><a href="{track}x">Unsubscribe</a>{pixel}',
            serial=serial,
            auth=_auth(esp, domain, esp),
            bounce=bounce,
            bulk=True,
            unsubscribe=f"https://unsubscribe.{esp}/u?t={_token(rng, 40)}",
            reply_to=f"hello@{domain}",
        )
    if family == "security_alert":
        # A genuine provider notice: wording that also fits phishing, authenticated by DMARC.
        return _msg(
            f"{brand.title()} Accounts <accounts@{domain}>",
            "Security alert: new sign-in",
            f"We noticed a new sign-in to your account. If this was not you, verify your account and change your "
            f"password at https://account.{domain}/security\n",
            f'<p>New sign-in. If this was not you, <a href="https://account.{domain}/security">verify your account</a>.</p>',
            serial=serial,
            auth=_auth(domain, domain, domain),
            bounce=f"no-reply@{domain}",
            bulk=False,
        )
    if family == "calendar_invite":
        return _msg(
            f"{rng.choice(['Alice', 'Bruno', 'Chen'])} Example <alice@{domain}>",
            f"Invitation: {word} planning",
            f"You are invited to {word} planning on Friday. Join: https://meet.{domain}/j/{ref}\n",
            f'<p>You are invited.</p><a href="https://meet.{domain}/j/{ref}">Join meeting</a>',
            serial=serial,
            auth=_auth(domain, domain, domain),
            bounce=f"alice@{domain}",
            bulk=False,
        )
    if family == "bank_statement":
        return _msg(
            f"{brand.title()} Bank <statements@{domain}>",
            "Your statement is ready",
            f"Your monthly statement is ready. Sign in to view it: https://online.{domain}/login\n",
            f'<p>Your statement is ready.</p><a href="https://online.{domain}/login">Sign in</a>',
            serial=serial,
            auth=_auth(domain, domain, domain),
            bounce=f"statements@{domain}",
            bulk=False,
        )
    if family == "code_notification":
        return _msg(
            f"{rng.choice(['Alice', 'Bruno', 'Chen'])} via {brand.title()} <notifications@{domain}>",
            f"Re: [{brand}/repo] fix {word} (#{ref})",
            f"Comment on #{ref}. View it on {brand.title()}: https://code.{domain}/repo/pull/{ref}\n",
            f'<p>Comment on #{ref}.</p><a href="https://code.{domain}/repo/pull/{ref}">View it</a>{pixel}',
            serial=serial,
            auth=_auth(domain, domain, esp),
            bounce=f"bounces+{ref}@{esp}",
            bulk=True,
            reply_to=f"{brand}/repo <repo@noreply.{domain}>",
            extra=(("X-GitHub-Reason", "comment"),),
        )
    raise ValueError(family)


def generate(seed: str, per_family: int = 15) -> list[tuple[str, bytes]]:
    """(family, raw message) in a fixed order, ``per_family`` messages per family."""
    rng = random.Random(seed)
    serial = 0
    out: list[tuple[str, bytes]] = []
    for family in FAMILIES:
        for _ in range(per_family):
            out.append((family, _one(family, rng, serial)))
            serial += 1
    return out
