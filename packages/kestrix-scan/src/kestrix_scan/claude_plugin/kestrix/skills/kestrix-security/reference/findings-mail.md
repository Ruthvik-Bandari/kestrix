# Mail finding ids (`kestrix mail analyze`)

Every finding has `id`, `analyzer`, `severity`, `title`, `explanation` and `evidence` (at most 300
characters). The ids below are stable reason codes. Source: `src/kestrix/mail/`.

## Verdict rules (applied in order)

1. `malicious`: any high finding from `sender`, `lookalike`, `links`, `attachments` or `intent`, or
   `mail.auth.dmarc_fail` together with any other medium or high finding.
2. `suspicious`: any other medium or high finding. A DMARC failure on its own lands here.
3. `suspicious` by combination: at least 3 distinct low findings from at least 2 different analyzers
   (info findings and `mail.sender.return_path_mismatch`, which lists and mail services produce routinely,
   do not count). The report's `verdict_reason` names them; it is `null` otherwise.
4. `insufficient_evidence`: no trusted authentication results (`mail.auth.missing`) and no other finding
   above info.
5. `clean`: none of the above. It means no check fired, not that the message is safe.

`heuristic_score` = sum of high 35, medium 15, low 5, info 0, capped at 100. Not a probability.

## Authentication (`auth`)

With `--trusted-authserv-id`, the first `Authentication-Results` header whose `authserv-id` matches is
read and trusted. Without it, the topmost header is read but unverified (`mail.auth.unverified`): anyone,
including the sender, can write it into a saved message, so its failures are reported but a pass lowers
nothing. Do not tell the user a sender is genuine from an unverified pass, and suggest
`--trusted-authserv-id` only for messages saved from the user's own mailbox, not for a sample someone sent.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.auth.dmarc_fail` | high | `dmarc=fail`. |
| `mail.auth.no_dmarc_with_failure` | medium | DMARC is `none` or absent, and SPF failed or every DKIM signature failed. |
| `mail.auth.spf_fail` | medium | `spf=fail`. |
| `mail.auth.spf_softfail` | low | `spf=softfail`. Forwarding often causes this. |
| `mail.auth.dkim_fail` | medium | Every DKIM result is `fail` or `permerror`. One passing signature outweighs a broken one, which mailing lists often cause. |
| `mail.auth.dkim_not_aligned` | low | DKIM passed, but no passing signature's domain (`header.d`, or the domain of `header.i`) is in the From domain's organization. |
| `mail.auth.missing` | info | No trusted `Authentication-Results` header. The checks cannot be judged; this leads to `insufficient_evidence`, never to a worse verdict. |
| `mail.auth.unverified` | info | No `--trusted-authserv-id`; the topmost header was read. The evidence names its `authserv-id` and results. A pass in it lowers nothing. |

## Sender (`sender`)

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.sender.reply_to_mismatch` | medium (low on list mail) | A `Reply-To` address is in another organization than `From` and is not the message's own mailing list (next row). Severity is `low` when the message has list headers and every such `Reply-To` is at a free-mail provider (Gmail, Outlook, Hotmail, Live, Yahoo, iCloud, Proton, QQ, 163, 126, Mykolab): on a list that is a participant's own setting. |
| `mail.sender.reply_to_mailing_list` | info | The message has a `List-Id`, `List-Post` or `List-Unsubscribe` header and a foreign `Reply-To` is in the same organization as a domain named there (the list identifier, a `mailto:` address or a URL), as when a list sets `Reply-To` to itself. It explains the `Reply-To` and adds nothing to the verdict. List headers are easy to forge; `Precedence: list` or `bulk` alone explains nothing. |
| `mail.sender.return_path_mismatch` | low | `Return-Path` is in another organization than `From`. Mailing lists and email service providers do this routinely. |
| `mail.sender.display_name_spoof` | high; medium when a domain appears among other words | The display name contains an email address or a domain outside the From organization. A bare word counts as a domain only with a common or two-letter top-level domain, so `invoice.pdf` does not. It is high when the display name holds an address or is nothing but the domain (`PayPal.com`), and medium when the domain is one word among others (`PayPal.com Billing`), which genuine newsletters also do. |
| `mail.sender.display_name_brand` | high | The display name contains the name of a protected domain (its first label, three characters or more) and `From` is outside that domain's organization. |
| `mail.sender.random_domain` | low | A label of the From domain looks machine-generated (see **Machine-generated names** below). |
| `mail.sender.outdated_mailer` | low | `X-Mailer` names a mail program discontinued long ago (`Outlook Express`, `Microsoft Internet Mail`, `Netscape Messenger` or `Communicator`, `Eudora`). Spam tools forge these; the header is easy to set, so it is a hint only. |

**Machine-generated names.** A host label (the top-level domain excluded, hyphenated labels judged piece by piece, punycode skipped) of 8 characters or more reads as machine-generated when it switches between letters and digits three or more times, as in `q7vk2mx9r4tz8wn3`, or has six consonants in a row. It is lexical only: a pronounceable random name such as `velomarquintasy` passes, and some click trackers and CDNs also use generated names.

## Look-alike domains (`lookalike`)

Needs `--protected-domain` except `mail.lookalike.mixed_script`.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.lookalike.homograph` | high | The host has non-ASCII (internationalized) letters and its skeleton equals a protected domain's, as with a Cyrillic `а` in `pаypal.com`. |
| `mail.lookalike.domain` | high for the From domain; medium for a link host | The skeleton equals the protected label, or is within Damerau-Levenshtein distance 1 of it (protected labels of 5 to 8 characters) or 2 (9 characters or more), as with `paypa1.com` or `rnicrosoft.com`. Shorter protected labels must match exactly after folding. |
| `mail.lookalike.brand_in_host` | medium | A dot- or hyphen-separated part of another organization's host folds to the protected label (3 characters or more), as in `paypal.com.account-verify.example` or `paypal-secure.example`. |
| `mail.lookalike.mixed_script` | medium | One label mixes Latin letters with Cyrillic or Greek ones. Raised with or without protected domains. |

## Links (`links`)

Links are read as text only, never visited.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.links.text_href_mismatch` | high | An anchor's visible text reads as a web address in another organization than both the link's real host and the From domain. |
| `mail.links.sender_domain_redirect` | low | The visible text shows the sender's own domain and the link goes through a host or path that looks like click tracking (for example `click.`, `/ls/click`). Newsletters do this; a forged sender is caught by the authentication findings instead. |
| `mail.links.sender_domain_mismatch` | medium | The visible text shows the sender's own domain, but the link goes to another site that does not look like click tracking. |
| `mail.links.userinfo` | high | The URL has text before `@`, as in `https://bank.com@evil.example`, which opens `evil.example`. |
| `mail.links.script_scheme` | high | The href uses `javascript:`, `data:` or `vbscript:`, also when split by spaces, tabs or control characters. |
| `mail.links.ip_host` | medium (info for private addresses) | The host is an IP address, including numeric forms such as `3232235777`. Severity is `info` when the address is not globally routable (private, loopback, link-local, documentation range): phishing kits use public addresses. |
| `mail.links.punycode_host` | medium | A host label is internationalized (`xn--`), written either way. |
| `mail.links.shortener` | low | The host is on a fixed list of URL shorteners such as `bit.ly`. |
| `mail.links.redirect_param` | low | A query parameter's value is another `http(s)://` or `//` URL. |
| `mail.links.insecure_login` | low | An `http:` link whose path contains `login`, `logon`, `signin`, `verify` or `password`. |
| `mail.links.random_host` | low | A link host has a machine-generated label (see **Machine-generated names** under Sender). Reported once per host. |
| `mail.links.plain_http` | low | At least half of the message's web links use `http:` rather than `https:`. Reported once per message, with the count as evidence (for example `2 of 2 web links use http`). |

## Attachments (`attachments`)

Attachments are hashed and sniffed, never opened or extracted.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.attachments.dangerous_type` | high; medium for `html`, `htm`, `svg` | The extension is one of `exe scr com pif bat cmd js jse vbs vbe wsf wsh ps1 hta lnk iso img vhd vhdx msi jar one chm cpl reg html htm svg`. |
| `mail.attachments.double_extension` | high | A document-like extension is followed by a high-risk one, as in `invoice.pdf.exe`. |
| `mail.attachments.magic_mismatch` | high when the content is a Windows program; medium otherwise | The first bytes (`MZ`, `PK\x03\x04`, `%PDF`, or the OLE signature) disagree with the extension or, without a known extension, the declared content type. |
| `mail.attachments.macro_office` | medium | A macro-enabled Office extension (`docm`, `xlsm`, `pptm` and similar), legacy OLE Office content (except `.msg`), or a ZIP-based file that contains `vbaProject.bin`. |
| `mail.attachments.encrypted_archive` | medium | A ZIP member is encrypted. Mail filters cannot scan it. |
| `mail.attachments.archive_dangerous_member` | high | A ZIP member has a high-risk extension from the list above. |

## Intent (`intent`, heuristic; English, plus Russian for gambling and prize offers)

| `id` | Severity | Raised for phrases such as |
| --- | --- | --- |
| `mail.intent.payment_change` | medium | "bank details have changed", "new account number", "wire transfer", "update your payment"; also "invoice attached" when an urgency cue is present (evidence `invoice attached + <urgency cue>`). |
| `mail.intent.gift_cards` | medium | A request: "buy some gift cards", "gift card codes", "iTunes cards", "scratch off the back". A mention such as "our gift cards never expire" does not fire. |
| `mail.intent.credential_request` | medium (low when a trusted authserv-id records DMARC pass) | "verify your account", "confirm your password", "sign in to continue", "unusual sign-in", and looser wording: "update your billing information", "restore your account", "your account has been limited", "suspicious activity", "click here to verify". Genuine provider alerts use these words, so when the header of a trusted authserv-id records DMARC pass it is low and the links decide; without one it stays medium. |
| `mail.intent.urgency` | low | "urgent", "immediately", "within 24 hours", "account will be suspended", "as soon as possible", "final notice". |
| `mail.intent.secrecy` | low | "keep this confidential", "don't tell anyone", "be discreet". |
| `mail.intent.gambling_offer` | medium | "free spins", "no deposit bonus", "100 FS" (upper case only), "casino bonus"; in Russian "фриспины", "бесплатные спины", "без депозита", "бонус на депозит". |
| `mail.intent.spam_offer` | medium | One of 23 classic spam-offer phrases: loans and mortgages ("credit card offers", "bad credit", "debt consolidation", "mortgage rates", "refinance now", "lowest interest rates"), health ("lose weight", "weight loss", "enlarge your", "online pharmacy", "no prescription"), home-based income ("be your own boss", "home-based business", "work from home opportunity", "make money online", "extra income", "easy money"), "100% guaranteed" and bulk e-mail lists ("bulk e-mail", "million addresses"). A discussion about spam uses them too. |
| `mail.intent.prize_claim` | medium | "you have won", "claim your prize", "lottery winner"; in Russian "вы выиграли", "ваш приз", "получите выигрыш". |
| `mail.intent.hidden_text` | low | The subject and text together hold 20 or more invisible characters (zero-width spaces and joiners, soft hyphens, word joiners, byte-order marks). The evidence gives the count and the most common one, for example `120 invisible characters, mostly U+200C`. Newsletters pad their preview line with a few; spam uses long runs. |
| `mail.intent.bec_pattern` | high | `payment_change` or `gift_cards` together with `urgency` or `secrecy`. The evidence names the families, for example `gift_cards with secrecy`. |

## Plain-language hints

- Authentication failures mean the sender's domain did not vouch for this message; forwarding and mailing
  lists can cause SPF or DKIM failures on genuine mail, so weigh them with the other findings.
- `display_name_*`, `lookalike.*` and `links.text_href_mismatch` are impersonation signs: describe who the
  message pretends to be and where it really comes from or links to.
- `intent.bec_pattern` is the business-email-compromise pattern: payment or gift-card request plus pressure
  or secrecy. Advise calling the requester on a known number before paying.
