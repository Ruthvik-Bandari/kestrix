// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { guide, list, note, p, section, see, steps, table } from "../blocks";
import type { DocPage } from "../model";
import { LIMITS_NAV, ref, toolOverview } from "./helpers";

/* Follows docs/modules/mail.md, docs/research/mail-benchmark.md and docs/api.md. */

const BASE = "tools/email";

export const emailPages: DocPage[] = [
  toolOverview("mail", BASE, [`${BASE}/how-it-works`, `${BASE}/using-it`, `${BASE}/findings`, `${BASE}/limits`]),
  {
    path: `${BASE}/how-it-works`,
    title: "Email check: how it works",
    nav: "How it works",
    summary: "The parser, the six analyzers, which authentication header is trusted, and how the verdict and score are decided.",
    sections: [
      ref("mail", "How it works"),
      section(
        "Which authentication results are trusted",
        p(
          "The `auth` analyzer reads `Authentication-Results` headers (RFC 8601). Anyone can write such a header, including the sender, so only one is trusted: by default the topmost one, which your provider adds last on delivery, or with `--trusted-authserv-id` the first one whose `authserv-id` matches. If none matches, the results count as missing. `ARC` results are not judged.",
        ),
      ),
      section(
        "How the verdict is decided",
        p("The rules are applied in this order:"),
        steps(
            "`malicious`: any high finding from the `sender`, `lookalike`, `links`, `attachments` or `intent` analyzers, or `mail.auth.dmarc_fail` together with any other medium or high finding.",
            "`suspicious`: any other medium or high finding. A DMARC failure on its own lands here.",
            "`suspicious` by combination: at least 3 distinct low findings from at least 2 different analyzers. Info findings never count, and neither does `mail.sender.return_path_mismatch`, which mailing lists and email service providers produce routinely. The report's `verdict_reason` names them.",
            "`insufficient_evidence`: no trusted authentication results (`mail.auth.missing`) and no other finding above info.",
            "`clean`: none of the above.",
        ),
        p("`heuristic_score` is the sum of per-severity weights of all findings (high 35, medium 15, low 5, info 0), capped at 100. It orders messages for attention. It is not a probability."),
      ),
      section(
        "Look-alike domains",
        p(
          "The `lookalike` analyzer compares the From domain and every `http(s)` link host (IP addresses excluded) with the protected domains you name. Hosts in the same organization as a protected domain, such as `mail.paypal.com` for `paypal.com`, are genuine and never flagged. A host is compared by its registrable label, after both sides are folded to a skeleton:",
        ),
        steps(
            "NFKC normalization, so fullwidth letters become ASCII, then lower case.",
            "A fixed table of letters that look Latin: Cyrillic, Greek, Armenian and one Latin-script letter.",
            "ASCII look-alikes: `0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, then `rn`→`m`, `vv`→`w`, `cl`→`d`.",
        ),
        p("The table is a curated subset of the Unicode confusables list, not all of it, so some look-alikes are missed."),
      ),
      section(
        "What the parser limits",
        table(
          ["Limit", "Value", "When exceeded"],
          [
            ["Message size", "25 MiB (10 MiB on the hosted service)", "`input_too_large`"],
            ["Header fields per part", "500", "`input_too_large`"],
            ["One header field", "16 KiB", "`input_too_large`"],
            ["One header block, checked on the raw bytes before parsing", "64 KiB", "`input_too_large`"],
            ["All header blocks together", "1 MiB", "`input_too_large`"],
            ["Parameters in one `Content-Type` or `Content-Disposition` field", "50", "`input_too_large`"],
            ["MIME nesting depth", "10", "`nesting_too_deep`"],
            ["MIME parts", "200", "`input_too_large`"],
            ["Decoded text scanned", "5 MiB of characters", "The rest is skipped; `counts.text_truncated` is true"],
            ["Links extracted", "500", "The rest are skipped; `counts.links_truncated` is true"],
            ["ZIP members listed", "1,000", "The rest are not listed"],
          ],
        ),
        p("Input with none of the usual message headers is rejected with `invalid_input` rather than reported as clean. Nothing is decompressed, rendered or executed."),
      ),
    ],
  },
  {
    path: `${BASE}/using-it`,
    title: "Email check: using it",
    nav: "Using it",
    summary: "Check a message in the dashboard or with `kestrix mail analyze`, and read the report.",
    sections: [
      section(
        "In the dashboard",
        p("Open the Email check page, choose or drop an `.eml` file, optionally list protected domains (comma-separated, up to 20) and your provider's `authserv-id`, and select Check message. The page explains how to save a message: in Gmail, ⋮ (More) → Download message; in Outlook, File → Save as."),
        p("The result shows the verdict with an icon and a word, never color alone; the heuristic score, labeled as a heuristic and not a probability; the counts and the message SHA-256; the findings grouped by severity, each with its title, explanation, evidence, analyzer and reason code; and the raw JSON report, which can be copied or downloaded."),
        p("Files over 25 MiB and more than 20 protected domains are refused in the browser before anything is sent. On the hosted service the file goes to Kestrix's server and is never stored."),
      ),
      section("On the command line", guide("mail")),
      section(
        "Options and exit codes",
        table(
          ["Command", "Options", "Exit codes"],
          [
            [
              "`kestrix mail analyze PATH`",
              "`--protected-domain D` (repeatable, at most 20), `--trusted-authserv-id X` (repeatable, at most 5), `--json`",
              "0 analysed; 2 rejected (for example larger than 25 MiB, or not an email message)",
            ],
          ],
        ),
        list(
          "`--protected-domain` names a domain you care about, such as your bank or your employer. A display name that contains its name on a message from another domain is flagged, and so are look-alikes of it in the From domain and link hosts.",
          "`--trusted-authserv-id` names your mail provider's `authserv-id`, the first word of the `Authentication-Results` header it adds, for example `mx.google.com`.",
        ),
        p("Rejections print `Rejected (<reason>): <detail>` to stderr."),
      ),
      section(
        "The report",
        table(
          ["Field", "Meaning"],
          [
            ["`schema_version`", "`1`"],
            ["`notice`", "The privacy and heuristic notice"],
            ["`sha256`", "SHA-256 of the raw message bytes"],
            ["`subject`", "Subject header, cut to 200 characters"],
            ["`from_address`", "The address in `From`, if one could be parsed"],
            ["`verdict`, `heuristic_score`", "See How it works"],
            ["`verdict_reason`", "`null`, or a sentence naming the low findings when several of them alone made the message `suspicious`"],
            ["`findings`", "Most severe first. Each has `id`, `analyzer`, `severity`, `title`, `explanation` and `evidence` (at most 300 characters)"],
            ["`counts`", "`parts`, `links`, `attachments`, and `text_truncated` / `links_truncated` when a limit was reached"],
          ],
        ),
        p("The report holds reason codes, hosts, the header values needed to explain a finding, file names and hashes. It never holds the message body, link text or attachment bytes, with one exception: an `intent` finding's evidence is the short cue phrase that matched, at most 60 characters."),
        see("Every finding id", `${BASE}/findings`),
      ),
    ],
  },
  {
    path: `${BASE}/findings`,
    title: "Email check: findings reference",
    nav: "Findings reference",
    summary: "Every reason code the email check can raise, with its severity and what raises it.",
    sections: [
      section(
        "How to read these tables",
        p("Each finding has a stable `id`, one of six analyzers, a severity (`high`, `medium`, `low` or `info`), a title, a plain-language explanation and the evidence behind it. Info findings never change a verdict."),
      ),
      section(
        "Authentication (auth)",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`mail.auth.dmarc_fail`", "high", "`dmarc=fail`."],
            ["`mail.auth.no_dmarc_with_failure`", "medium", "DMARC is `none` or absent, and SPF failed or every DKIM signature failed."],
            ["`mail.auth.spf_fail`", "medium", "`spf=fail`."],
            ["`mail.auth.spf_softfail`", "low", "`spf=softfail`. Forwarding often causes this."],
            ["`mail.auth.dkim_fail`", "medium", "Every DKIM result is `fail` or `permerror`. One passing signature outweighs a broken one, which mailing lists often cause."],
            ["`mail.auth.dkim_not_aligned`", "low", "DKIM passed, but no passing signature's domain is in the From domain's organization."],
            ["`mail.auth.missing`", "info", "No trusted `Authentication-Results` header. The checks cannot be judged; this leads to `insufficient_evidence`, never to a worse verdict."],
          ],
        ),
      ),
      section(
        "Sender (sender)",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`mail.sender.reply_to_mismatch`", "medium", "A `Reply-To` address is in another organization than `From` and is not the message's own mailing list."],
            ["`mail.sender.reply_to_mailing_list`", "info", "The message has list headers and a foreign `Reply-To` is in the same organization as a domain named there, as when a list sets `Reply-To` to itself. It explains the `Reply-To` and adds nothing to the verdict."],
            ["`mail.sender.return_path_mismatch`", "low", "`Return-Path` is in another organization than `From`. Mailing lists and email service providers do this routinely."],
            ["`mail.sender.display_name_spoof`", "high; medium when a domain appears among other words", "The display name contains an email address or a domain outside the From organization."],
            ["`mail.sender.display_name_brand`", "high", "The display name contains the name of a protected domain and `From` is outside that domain's organization."],
            ["`mail.sender.random_domain`", "low", "A label of the From domain looks machine-generated."],
            ["`mail.sender.outdated_mailer`", "low", "`X-Mailer` names a mail program discontinued long ago. Spam tools forge these; the header is easy to set, so it is a hint only."],
          ],
        ),
      ),
      section(
        "Look-alike domains (lookalike)",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`mail.lookalike.homograph`", "high", "The host has non-ASCII letters and its skeleton equals a protected domain's, as with a Cyrillic `а` in `pаypal.com`."],
            ["`mail.lookalike.domain`", "high for the From domain; medium for a link host", "The skeleton equals the protected label, or is within a small edit distance of it, as with `paypa1.com` or `rnicrosoft.com`."],
            ["`mail.lookalike.brand_in_host`", "medium", "A dot- or hyphen-separated part of another organization's host folds to the protected label, as in `paypal.com.account-verify.example`."],
            ["`mail.lookalike.mixed_script`", "medium", "One label mixes Latin letters with Cyrillic or Greek ones. Raised with or without protected domains."],
          ],
        ),
      ),
      section(
        "Links (links)",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`mail.links.text_href_mismatch`", "high", "An anchor's visible text reads as a web address in another organization than both the link's real host and the From domain."],
            ["`mail.links.sender_domain_redirect`", "low", "The visible text shows the sender's own domain and the link goes through a host or path that looks like click tracking."],
            ["`mail.links.sender_domain_mismatch`", "medium", "The visible text shows the sender's own domain, but the link goes to another site that does not look like click tracking."],
            ["`mail.links.userinfo`", "high", "The URL has text before `@`, as in `https://bank.com@evil.example`, which opens `evil.example`."],
            ["`mail.links.script_scheme`", "high", "The href uses `javascript:`, `data:` or `vbscript:`, also when split by spaces, tabs or control characters."],
            ["`mail.links.ip_host`", "medium", "The host is an IP address, including numeric forms such as `3232235777`."],
            ["`mail.links.punycode_host`", "medium", "A host label is internationalized (`xn--`), written either way."],
            ["`mail.links.shortener`", "low", "The host is on a fixed list of URL shorteners such as `bit.ly`."],
            ["`mail.links.redirect_param`", "low", "A query parameter's value is another `http(s)://` or `//` URL."],
            ["`mail.links.insecure_login`", "low", "An `http:` link whose path contains `login`, `logon`, `signin`, `verify` or `password`."],
            ["`mail.links.random_host`", "low", "A link host has a machine-generated label. Reported once per host."],
            ["`mail.links.plain_http`", "low", "At least half of the message's web links use `http:` rather than `https:`. Reported once per message."],
          ],
        ),
        p("Links are checked as text only and are never visited. Each reason is reported once per host, and at most 50 link findings are reported."),
      ),
      section(
        "Attachments (attachments)",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`mail.attachments.dangerous_type`", "high; medium for `html`, `htm`, `svg`", "The extension is on the list of types that can run code or open a fake page (`exe`, `scr`, `bat`, `js`, `vbs`, `ps1`, `lnk`, `iso`, `msi`, `jar` and others)."],
            ["`mail.attachments.double_extension`", "high", "A document-like extension is followed by a high-risk one, as in `invoice.pdf.exe`."],
            ["`mail.attachments.magic_mismatch`", "high when the content is a Windows program; medium otherwise", "The first bytes disagree with the extension or, without a known extension, the declared content type."],
            ["`mail.attachments.macro_office`", "medium", "A macro-enabled Office extension, legacy OLE Office content (except `.msg`), or a ZIP-based file that contains `vbaProject.bin`."],
            ["`mail.attachments.encrypted_archive`", "medium", "A ZIP member is encrypted. Mail filters cannot scan it."],
            ["`mail.attachments.archive_dangerous_member`", "high", "A ZIP member has a high-risk extension."],
          ],
        ),
        p("Each attachment is hashed with SHA-256. ZIP-based files are listed from their central directory (at most 1,000 member names); nothing is decompressed."),
      ),
      section(
        "Intent (intent)",
        p("The `intent` analyzer looks for the wording of business email compromise (BEC), credential phishing and spam offers in the subject and the decoded text. It uses small, curated, case-insensitive phrase lists, in English for every family and also in Russian for the gambling and prize families. Each family is reported at most once, with the first matched phrase as evidence."),
        table(
          ["id", "Severity", "Raised for phrases such as"],
          [
            ["`mail.intent.payment_change`", "medium", "\"bank details have changed\", \"new account number\", \"wire transfer\", \"update your payment\"; also \"invoice attached\" when an urgency cue is present."],
            ["`mail.intent.gift_cards`", "medium", "A request: \"buy some gift cards\", \"gift card codes\", \"scratch off the back\". A mention such as \"our gift cards never expire\" does not fire."],
            ["`mail.intent.credential_request`", "medium (low when DMARC passes)", "\"verify your account\", \"confirm your password\", \"sign in to continue\", \"suspicious activity\", \"click here to verify\"."],
            ["`mail.intent.urgency`", "low", "\"urgent\", \"immediately\", \"within 24 hours\", \"account will be suspended\", \"final notice\"."],
            ["`mail.intent.secrecy`", "low", "\"keep this confidential\", \"don't tell anyone\", \"be discreet\"."],
            ["`mail.intent.gambling_offer`", "medium", "\"free spins\", \"no deposit bonus\", \"casino bonus\"; also in Russian."],
            ["`mail.intent.spam_offer`", "medium", "One of 23 classic spam-offer phrases on loans, health, home-based income, \"100% guaranteed\" and bulk e-mail lists."],
            ["`mail.intent.prize_claim`", "medium", "\"you have won\", \"claim your prize\", \"lottery winner\"; also in Russian."],
            ["`mail.intent.hidden_text`", "low", "The subject and text together hold 20 or more invisible characters (zero-width spaces and joiners, soft hyphens, word joiners, byte-order marks)."],
            ["`mail.intent.bec_pattern`", "high", "`payment_change` or `gift_cards` together with `urgency` or `secrecy`. The evidence names the families."],
          ],
        ),
        note("Ordinary mail can use the same words, and the lists miss paraphrases and other languages. Genuine provider alerts use credential wording, which is why that finding drops to low when DMARC proves the From domain sent the message.", "caution"),
      ),
    ],
  },
  {
    path: `${BASE}/limits`,
    title: "Email check: limits and measured accuracy",
    nav: LIMITS_NAV,
    summary: "What the email check cannot see, and the one measurement of how often it flags phishing, spam and normal mail.",
    sections: [
      ref("mail", "Limits"),
      section(
        "Measured accuracy",
        p(
          "The rules were measured once, on a locked test that was never used for tuning: 10,897 messages (3,019 phishing, 238 spam, 7,550 normal: 6,014 Enron and 1,536 SpamAssassin) from public corpora, in 135 split groups. Intervals are 95% group-bootstrap intervals; SpamAssassin normal mail has too few groups for one.",
        ),
        table(
          ["Measure", "Old rules", "Current rules"],
          [
            ["Phishing flagged (suspicious or malicious)", "49.4% (41.1–58.2)", "61.2% (54.0–69.3)"],
            ["Phishing malicious", "13.6% (8.9–19.7)", "10.6% (7.8–14.5)"],
            ["Spam flagged", "31.1% (17.1–37.2)", "50.0% (27.9–54.9)"],
            ["SpamAssassin normal mail flagged", "20.1%", "1.0%"],
            ["Enron normal mail flagged", "1.1% (0.4–2.0)", "1.3% (0.6–2.2)"],
            ["All normal mail flagged", "5.0% (0.8–9.9)", "1.2% (0.7–2.0)"],
            ["Precision, phishing against normal mail (flagged)", "79.8% (51.3–97.2)", "95.2% (87.0–98.4)"],
          ],
          "Locked test, content-only feature set, 2026-10-22",
        ),
      ),
      section(
        "How to read it",
        list(
          "The current rules flag about six in ten phishing messages and half of the spam in this test. They miss the rest.",
          "Fewer messages are called malicious (13.6% to 10.6% of phishing): the trade accepted for far fewer malicious verdicts on normal mail.",
          "The normal mail is from 1999 to 2005 and Enron lacks most headers, so false alarms on today's mail are not measured. Spam has only 238 test messages and wide intervals.",
          "Almost no message in these corpora carries a trusted `Authentication-Results` header, so the authentication checks have barely been exercised by this benchmark.",
          "A weighting learned from the same data flagged only 34.3% of phishing on the same messages (94.3% precision) and was not adopted.",
          "The locked test is spent: any later change to the rules needs new held-out data.",
        ),
        note("The heuristic score is not a probability, and none of these rates says how a particular message will fare.", "caution"),
      ),
    ],
  },
];
