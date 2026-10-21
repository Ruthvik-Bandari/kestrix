# Privacy notice (draft)

> Draft — to be reviewed by the owner before launch. Not legal advice.

_Draft of October 21, 2026_

This notice covers the hosted Kestrix website, where you sign in with Google or GitHub and use the website check, file and link forensics, and the email check in your browser. It does not cover the open-source Kestrix you install on your own computer, which has no accounts and sends nothing to us.

In short: we keep your email address and display name so you can sign in, we do not keep the files, emails or links you check, and you can delete your account at any time.

## What we collect

When you sign in, we store one account record with:

- the sign-in provider you used (Google or GitHub) and that provider's identifier for your account;
- your verified email address;
- your display name;
- when the account was created and when you last signed in, when you agreed to the terms of use if you signed up with the Sign up option, and, if we disable it for abuse, when that happened.

We do not store passwords, and we do not keep the access tokens Google or GitHub give us; they are used once during sign-in and discarded. We ask Google only for your basic profile and email (openid, email, profile) and GitHub only for your profile and email addresses (read:user, user:email).

## Sessions and cookies

We set three cookies, all needed to sign you in. We use no advertising, analytics or tracking cookies.

- __Host-kx_at shows that you are signed in. It lasts 15 minutes and is renewed automatically while you use the site.
- __Host-kx_rt renews __Host-kx_at. It is replaced every time it is used and stops working 7 days after its last use or 30 days after sign-in, whichever comes first, or when you sign out. We store only a keyed hash of it, not the cookie value.
- __Host-kx_login lasts 10 minutes and exists only while a sign-in is in progress, to make sure the sign-in finishes in the browser that started it.

While a sign-in is in progress we also keep a short record of the attempt (which provider, security codes for the exchange, the page to return to, and whether you chose Log in or Sign up). It expires after 10 minutes and is deleted when used.

Your browser also remembers your light or dark theme choice and which help panels you closed. That stays on your device and is never sent to us.

## Files, emails and links you check

- Files and emails you upload are analyzed in a separate, short-lived process on our server. While an upload is received and analyzed it is held in memory, and an upload larger than 1 MB may be spooled briefly to temporary disk storage; it is deleted as soon as the analysis ends. Uploads are never written to our database and are not kept after the analysis.
- The report is sent back to your browser. We do not keep a copy.
- Links you check in forensics are examined as text; Kestrix does not visit them.
- For a website check, our server sends one request to the site you enter (following up to five redirects) plus one secure-connection handshake. That site sees the request coming from our server, identified as Kestrix. We do not store the address you checked or the result; our logs keep only a keyed hash of the site's host name (see Logs).

## Logs

For each request our server logs the time, the kind of request and which page or API route it was for, the result code, how long it took, and a salted hash of your account identifier (not your email or name). Failed sign-ins add a short reason code.

For each website check we also log your hashed account identifier and a keyed hash of the site's host name, not the name itself. If a site's owner reports abuse from our service, we can hash the host name they give us and find the account that checked it; the hash cannot be turned back into a host name.

Logs never contain file contents, file names, email messages, email addresses, the websites or links you check, cookies or tokens. Log retention: [retention period to be set by the owner].

## Rate limits

To keep the service available and to prevent abuse, we count requests: 20 website checks per account per hour, 120 analyses per account per hour, one check or analysis at a time per account, and 20 sign-in starts, 10 returns from Google or GitHub and 60 sign-in renewals per network address per 10 minutes (for IPv6, per /64 network). The counters live only in the server's memory and are not stored.

## How long we keep your data, and deleting it

Your account record stays until you delete it. Choose Delete account in the account menu: it removes your account record and ends every sign-in immediately. Signing out ends that sign-in at once.

Backups: our hosting provider keeps daily snapshots of the storage volume that holds the account database, for 14 days. After you delete your account, its record can remain in those snapshots until they expire, at most 14 days later.

If an account is used to abuse the service, we can disable it: it can no longer sign in and its sign-ins end within 30 seconds. The account record, with the time it was disabled, stays until it is deleted.

## Who else is involved

- Google and GitHub, when you choose to sign in with them. Their own privacy policies apply to your use of their sign-in.
- Our hosting provider, which runs the server and stores the account database: [hosting provider to be named by the owner].
- The website you choose to check receives one request from our server.

We do not sell or share your data with anyone else, and we show no ads.

## Security

The site is served only over HTTPS. Sign-in cookies are Secure and HttpOnly, every change you make needs a per-sign-in security token, and the renewal tokens in our database are stored only as keyed hashes. No system is perfectly secure, but we design Kestrix to keep as little as possible.

## Children

The service is not directed at children. Do not use it if you are under 13, or under the minimum age for consenting to online services where you live.

## Your choices and rights

You can see what we hold about you (your name, email and sign-in provider) in the account menu, and delete it at any time. For any other request about your data, contact [contact email to be added by the owner].

## Changes to this notice

If we change how we handle data, we will update this page and its date before the change takes effect.

## Contact

Questions about privacy: [contact email to be added by the owner].
