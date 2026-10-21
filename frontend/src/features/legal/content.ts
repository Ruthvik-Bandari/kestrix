// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/*
 * DRAFT privacy notice and terms for the hosted service (ADR 0004, slice H4). Every statement
 * describes behavior in src/kestrix/server and docs/hosted.md; placeholders in [brackets] are
 * decisions the owner still has to make. docs/legal/*-draft.md carry the same text, and a test
 * (legal.test.tsx) keeps the two in step.
 */

export const DRAFT_BANNER =
  "Draft — to be reviewed by the owner before launch. Not legal advice.";

export type Block = { p: string } | { ul: string[] };

export interface LegalSection {
  heading: string;
  blocks: Block[];
}

export interface LegalDoc {
  title: string;
  updated: string;
  intro: string[];
  sections: LegalSection[];
}

const UPDATED = "Draft of October 21, 2026";
const CONTACT = "[contact email to be added by the owner]";

export const privacy: LegalDoc = {
  title: "Privacy notice",
  updated: UPDATED,
  intro: [
    "This notice covers the hosted Kestrix website, where you sign in with Google or GitHub and use the website check, file and link forensics, and the email check in your browser. It does not cover the open-source Kestrix you install on your own computer, which has no accounts and sends nothing to us.",
    "In short: we keep your email address and display name so you can sign in, we do not keep the files or emails you upload, we keep the reports of your checks for 30 days so you can see your history (you can turn this off), and you can delete your account at any time.",
  ],
  sections: [
    {
      heading: "What we collect",
      blocks: [
        { p: "When you sign in, we store one account record with:" },
        {
          ul: [
            "the sign-in provider you used (Google or GitHub) and that provider's identifier for your account;",
            "your verified email address;",
            "your display name;",
            "when the account was created and when you last signed in, when you agreed to the terms of use if you signed up with the Sign up option, and, if we disable it for abuse, when that happened.",
          ],
        },
        {
          p: "We do not store passwords, and we do not keep the access tokens Google or GitHub give us; they are used once during sign-in and discarded. We ask Google only for your basic profile and email (openid, email, profile) and GitHub only for your profile and email addresses (read:user, user:email).",
        },
      ],
    },
    {
      heading: "Sessions and cookies",
      blocks: [
        {
          p: "We set three cookies, all needed to sign you in. We use no advertising, analytics or tracking cookies.",
        },
        {
          ul: [
            "__Host-kx_at shows that you are signed in. It lasts 15 minutes and is renewed automatically while you use the site.",
            "__Host-kx_rt renews __Host-kx_at. It is replaced every time it is used and stops working 7 days after its last use or 30 days after sign-in, whichever comes first, or when you sign out. We store only a keyed hash of it, not the cookie value.",
            "__Host-kx_login lasts 10 minutes and exists only while a sign-in is in progress, to make sure the sign-in finishes in the browser that started it.",
          ],
        },
        {
          p: "While a sign-in is in progress we also keep a short record of the attempt (which provider, security codes for the exchange, the page to return to, and whether you chose Log in or Sign up). It expires after 10 minutes and is deleted when used.",
        },
        {
          p: "Your browser also remembers your light or dark theme choice and which help panels you closed. That stays on your device and is never sent to us.",
        },
      ],
    },
    {
      heading: "Files, emails and links you check",
      blocks: [
        {
          ul: [
            "Files and emails you upload are analyzed in a separate, short-lived process on our server. While an upload is received and analyzed it is held in memory, and an upload larger than 1 MB may be spooled briefly to temporary disk storage; it is deleted as soon as the analysis ends. Uploads are never written to our database and are not kept after the analysis.",
            "The report is sent back to your browser. Unless you have turned history off, we also keep an encrypted copy of the report for 30 days (see Your result history).",
            "Links you check in forensics are examined as text; Kestrix does not visit them.",
            "For a website check, our server sends read-only GET requests to the site you enter: one page if you choose \"Just this page\", otherwise up to 50 pages (the page you enter, pages it links to, its sitemap and six common login addresses) plus up to 15 more for the sitemap and redirects, and one secure-connection handshake. That site sees the request coming from our server, identified as Kestrix. Apart from your result history, we do not store the address you checked or the result; our logs keep only a keyed hash of the site's host name (see Logs).",
          ],
        },
      ],
    },
    {
      heading: "Your result history",
      blocks: [
        {
          p: "So you can look back at recent results, we keep the report of each successful check you run (email check, website check, file analysis and link check) on your account for 30 days. The Recent results page lists them. History is on when you sign up; you can turn it off at any time.",
        },
        {
          ul: [
            "which tool produced it and when;",
            "a short summary for the list: the verdict, grade or highest severity, and the number of findings;",
            "the full report, encrypted.",
          ],
        },
        {
          p: "A report holds what the check found. For an email that includes its subject line, the sender's address and short pieces of evidence such as a header value, a link's host, an attachment's file name or a matched warning phrase; for a file, its name, size, hashes and any metadata found in it, such as the location stored in a photo; for a link or a website, its address and what was found. We never store the files or emails you upload, and an email report never contains the message body.",
        },
        {
          p: "Reports are encrypted on our server with AES-256-GCM under a key kept outside the database, and each one is bound to your account. The short summary is not encrypted, so the list can be shown without decrypting every report.",
        },
        {
          p: "Reports are deleted automatically 30 days after the check. On the Recent results page you can delete one result or all of them, and in Settings you can turn history off: turning it off deletes every stored result and stops keeping new ones. Deleting your account deletes your history too.",
        },
      ],
    },
    {
      heading: "Logs",
      blocks: [
        {
          p: "For each request our server logs the time, the kind of request and which page or API route it was for, the result code, how long it took, and a salted hash of your account identifier (not your email or name). Failed sign-ins add a short reason code.",
        },
        {
          p: "For each website check we also log your hashed account identifier and a keyed hash of the site's host name, not the name itself. If a site's owner reports abuse from our service, we can hash the host name they give us and find the account that checked it; the hash cannot be turned back into a host name.",
        },
        {
          p: "Logs never contain file contents, file names, email messages, email addresses, the websites or links you check, the content of your reports, cookies or tokens. Log retention: [retention period to be set by the owner].",
        },
      ],
    },
    {
      heading: "Rate limits",
      blocks: [
        {
          p: "To keep the service available and to prevent abuse, we count requests: 20 website checks per account per hour, 120 analyses per account per hour, one check or analysis at a time per account, 120 history changes (deleting results or changing the history setting) per account per hour, and 20 sign-in starts, 10 returns from Google or GitHub and 60 sign-in renewals per network address per 10 minutes (for IPv6, per /64 network). The counters live only in the server's memory and are not stored.",
        },
      ],
    },
    {
      heading: "How long we keep your data, and deleting it",
      blocks: [
        {
          p: "Your account record stays until you delete it. Choose Delete account in the account menu: it removes your account record and your result history and ends every sign-in immediately. Signing out ends that sign-in at once. Result reports are deleted 30 days after the check, or sooner if you delete them or turn history off.",
        },
        {
          p: "Backups: our hosting provider keeps daily snapshots of the storage volume that holds the account database and the result history, for 14 days. After you delete your account or a result, it can remain in those snapshots until they expire, at most 14 days later; reports in a snapshot stay encrypted.",
        },
        {
          p: "If an account is used to abuse the service, we can disable it: it can no longer sign in and its sign-ins end within 30 seconds. The account record, with the time it was disabled, stays until it is deleted.",
        },
      ],
    },
    {
      heading: "Who else is involved",
      blocks: [
        {
          ul: [
            "Google and GitHub, when you choose to sign in with them. Their own privacy policies apply to your use of their sign-in.",
            "Our hosting provider, which runs the server and stores the account database: [hosting provider to be named by the owner].",
            "The website you choose to check receives read-only requests from our server: one, or up to 65 for a whole-site check.",
          ],
        },
        {
          p: "We do not sell or share your data with anyone else, and we show no ads.",
        },
      ],
    },
    {
      heading: "Security",
      blocks: [
        {
          p: "The site is served only over HTTPS. Sign-in cookies are Secure and HttpOnly, every change you make needs a per-sign-in security token, the renewal tokens in our database are stored only as keyed hashes, and your result reports are encrypted at rest. No system is perfectly secure, but we design Kestrix to keep as little as possible.",
        },
      ],
    },
    {
      heading: "Children",
      blocks: [
        {
          p: "The service is not directed at children. Do not use it if you are under 13, or under the minimum age for consenting to online services where you live.",
        },
      ],
    },
    {
      heading: "Your choices and rights",
      blocks: [
        {
          p: `You can see what we hold about you (your name, email and sign-in provider in the account menu, and your results on the Recent results page), and delete it at any time. For any other request about your data, contact ${CONTACT}.`,
        },
      ],
    },
    {
      heading: "Changes to this notice",
      blocks: [
        {
          p: "If we change how we handle data, we will update this page and its date before the change takes effect.",
        },
      ],
    },
    {
      heading: "Contact",
      blocks: [{ p: `Questions about privacy: ${CONTACT}.` }],
    },
  ],
};

export const terms: LegalDoc = {
  title: "Terms of use",
  updated: UPDATED,
  intro: [
    "These terms cover the hosted Kestrix website. The open-source Kestrix software is licensed separately under the Apache License 2.0; these terms do not change that license.",
  ],
  sections: [
    {
      heading: "The service",
      blocks: [
        {
          p: "The hosted service lets you check a website's HTTPS setup and security headers, analyze a file or a link, and check a saved email, in your browser. It is free and offered as a preview. Detection repair, the Bitcoin tools and the AI guardian are available only in the desktop app.",
        },
      ],
    },
    {
      heading: "Your account",
      blocks: [
        {
          p: "You sign in with a Google or GitHub account. Keep that account secure; anything done while you are signed in is treated as done by you. You can delete your Kestrix account at any time from the account menu.",
        },
      ],
    },
    {
      heading: "Acceptable use",
      blocks: [
        { p: "You agree to:" },
        {
          ul: [
            "check only websites you own or are authorized to test, and confirm that before each website check;",
            "upload only files and emails you have the right to share with us for analysis;",
            "not try to get around the rate limits, the sign-in or other protections, or use the service to reach private or internal networks;",
            "not overload, probe or attack the service or the websites you check, or use it to harm anyone.",
          ],
        },
        { p: "We may suspend or delete accounts that break these rules." },
      ],
    },
    {
      heading: "Limits and availability",
      blocks: [
        {
          p: "Requests are limited (currently 20 website checks and 120 analyses per account per hour). The service may change, be unavailable, or end, and we do not promise any particular uptime.",
        },
      ],
    },
    {
      heading: "Results",
      blocks: [
        {
          p: "Kestrix reports what its checks found and why. Grades and scores come from fixed rules and heuristics; they are not probabilities or guarantees. A clean result does not mean a site, file or email is safe, and Kestrix does not replace a professional security assessment. Use the results at your own judgment.",
        },
      ],
    },
    {
      heading: "No warranty",
      blocks: [
        {
          p: 'The service is provided "as is", without warranties of any kind, to the extent the law allows. [Limitation of liability wording to be written by the owner.]',
        },
      ],
    },
    {
      heading: "Privacy",
      blocks: [
        { p: "How we handle your data is described in the privacy notice." },
      ],
    },
    {
      heading: "Changes and governing law",
      blocks: [
        {
          p: "We will post changes to these terms on this page and update its date. Governing law and venue: [to be set by the owner].",
        },
      ],
    },
    {
      heading: "Contact",
      blocks: [{ p: `Questions about these terms: ${CONTACT}.` }],
    },
  ],
};
