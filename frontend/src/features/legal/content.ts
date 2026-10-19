// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/*
 * DRAFT privacy notice and terms for the hosted service (ADR 0004, slice H4). Every statement
 * describes behavior in src/kestrix/server and docs/hosted.md; placeholders in [brackets] are
 * decisions the owner still has to make. docs/legal/*-draft.md carry the same text, and a test
 * (legal.test.tsx) keeps the two in step.
 */

export const DRAFT_BANNER = "Draft — to be reviewed by the owner before launch. Not legal advice.";

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

const UPDATED = "Draft of October 19, 2026";
const CONTACT = "[contact email to be added by the owner]";

export const privacy: LegalDoc = {
  title: "Privacy notice",
  updated: UPDATED,
  intro: [
    "This notice covers the hosted Kestrix website, where you sign in with Google or GitHub and use the website check, file and link forensics, and the email check in your browser. It does not cover the open-source Kestrix you install on your own computer, which has no accounts and sends nothing to us.",
    "In short: we keep your email address and display name so you can sign in, we do not keep the files, emails or links you check, and you can delete your account at any time.",
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
            "when the account was created and when you last signed in.",
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
        { p: "We set two cookies, both needed to sign you in. We use no advertising, analytics or tracking cookies." },
        {
          ul: [
            "__Host-kx_session keeps you signed in. It ends after 7 days without use or 30 days after sign-in, whichever comes first, and is deleted when you sign out. We store only a keyed hash of it, not the cookie value.",
            "__Host-kx_login lasts 10 minutes and exists only while a sign-in is in progress, to make sure the sign-in finishes in the browser that started it.",
          ],
        },
        {
          p: "While a sign-in is in progress we also keep a short record of the attempt (which provider, security codes for the exchange, and the page to return to). It expires after 10 minutes and is deleted when used.",
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
            "Files and emails you upload are analyzed in memory (very large uploads may pass through an unnamed temporary file while they are processed). They are never written to our database and are not kept after the analysis.",
            "The report is sent back to your browser. We do not keep a copy.",
            "Links you check in forensics are examined as text; Kestrix does not visit them.",
            "For a website check, our server sends one request to the site you enter (following up to five redirects) plus one secure-connection handshake. That site sees the request coming from our server, identified as Kestrix. We do not store the address you checked or the result.",
          ],
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
          p: "Logs never contain file contents, file names, email messages, email addresses, the websites or links you check, cookies or tokens. Log retention: [retention period to be set by the owner].",
        },
      ],
    },
    {
      heading: "Rate limits",
      blocks: [
        {
          p: "To keep the service available and to prevent abuse, we count requests: 20 website checks per account per hour, 120 analyses per account per hour, and 10 sign-in attempts per network address per 10 minutes. The counters live only in the server's memory and are not stored.",
        },
      ],
    },
    {
      heading: "How long we keep your data, and deleting it",
      blocks: [
        {
          p: "Your account record stays until you delete it. Choose Delete account in the account menu: it removes your account record and every session immediately. Signing out deletes that session.",
        },
        { p: "Backups: [the owner will describe any backups of the account database and how long they last]." },
      ],
    },
    {
      heading: "Who else is involved",
      blocks: [
        {
          ul: [
            "Google and GitHub, when you choose to sign in with them. Their own privacy policies apply to your use of their sign-in.",
            "Our hosting provider, which runs the server and stores the account database: [hosting provider to be named by the owner].",
            "The website you choose to check receives one request from our server.",
          ],
        },
        { p: "We do not sell or share your data with anyone else, and we show no ads." },
      ],
    },
    {
      heading: "Security",
      blocks: [
        {
          p: "The site is served only over HTTPS. Session cookies are Secure and HttpOnly, every change you make needs a per-session security token, and the session identifiers in our database are stored only as keyed hashes. No system is perfectly secure, but we design Kestrix to keep as little as possible.",
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
          p: `You can see what we hold about you (your name, email and sign-in provider) in the account menu, and delete it at any time. For any other request about your data, contact ${CONTACT}.`,
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
      blocks: [{ p: "How we handle your data is described in the privacy notice." }],
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
