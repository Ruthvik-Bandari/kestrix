# ADR 0008: Per-user result history

- Status: accepted
- Date: 2026-10-21
- Decision owner: Ruthvik Bandari
- Amends: [ADR 0004](0004-hosted-mode.md), "Uploads are never stored" (reports were not kept either)

## Context

The dashboard gains a Recent results page. Users want to look back at the email checks, website checks and file
or link analyses they ran, without running them again. Until now the hosted service kept nothing after answering,
and the privacy draft said so. Uploaded files and emails must still never be stored.

## Decision

1. **Store the report, never the input.** After a 200 response from `POST /api/mail/analyze`, `/api/webcheck`,
   `/api/forensics/file` or `/api/forensics/url`, an ASGI middleware (`HistoryRecorder`, innermost) copies the JSON
   response body into the history. It never reads the request, so file bytes and email messages cannot reach it.
   The mail report already excludes the message body (its only body-derived text is a matched intent cue of at most
   60 characters). Responses over 2 MiB and failed requests are not recorded, and a recording failure never changes
   the response. The module routes are unchanged (one core, thin adapters).
2. **Row shape.** A random 128-bit id (`secrets.token_urlsafe(16)`), the user id, the tool (`mail`, `webcheck`,
   `forensics_file`, `forensics_url`), `created_at`, an unencrypted list summary (the verdict, grade, URL level or
   highest file-finding severity, and the number of findings) and the report. The summary is a fixed vocabulary,
   so listing never decrypts reports.
3. **Encryption at rest (hosted).** AES-256-GCM (`cryptography`, added to the `kestrix[hosted]` extra) under
   `KESTRIX_HISTORY_KEY`, 32 random bytes in base64, required in hosted mode. Each row has a random 96-bit nonce and
   uses `kestrix-history/v1 | row id | user id | tool` as associated data, so a ciphertext copied to another row or
   user fails authentication. Rows store a key id (the first 16 hex characters of HMAC-SHA256(key,
   `kestrix-history-key-id`)). `KESTRIX_HISTORY_KEY_PREVIOUS` decrypts rows written under the previous key; new rows
   always use the current one. Since rows live at most 30 days, the previous key can be removed 30 days after a
   rotation; no re-encryption job is needed. A row that cannot be decrypted is treated as missing (404).
4. **Retention: 30 days.** Older rows are deleted on every write and when the store opens, and reads filter them
   out, so `GET` routes stay side-effect free.
5. **Ownership and control.** Every query is scoped to the caller's user id; another user's id answers 404, exactly
   like a missing one. History is on by default (stated on the Sign up tab and in the privacy notice). Users can
   delete one result, delete all, or turn history off (`PUT /api/settings/history`), which deletes their rows and
   stops recording. Account deletion deletes the rows and the setting. On the hosted service all writes go through
   the existing gate: a session, the CSRF header, and a new per-user bucket of 120 history writes per hour.
6. **Storage.** A separate SQLite file beside the accounts database (`kestrix.db` → `kestrix-history.db`), created
   `0600` in a `0700` directory, with `secure_delete` and a WAL checkpoint after bulk deletions. Keeping it apart
   leaves the accounts schema (and its start-up schema check) untouched.
7. **Local mode.** The same routes and retention for the single local user, in `history.sqlite3` in the config
   folder (`0600`), unencrypted: the file is on the user's own machine next to the rest of their Kestrix data, and a
   key would have to be stored beside it, which adds no protection.
8. **Logs** record only the tool and the report size, never report content.

## Consequences

- The privacy draft and the sign-in card now say that reports are kept for 30 days and how to turn that off.
- Reports do contain personal data: an email's subject and sender, a file's name, hashes and metadata (such as
  photo GPS), and checked URLs. Anyone holding both the history database and the key can read them; volume snapshots
  alone cannot. The unencrypted summary reveals which tools a user ran, when, and the verdicts.
- Losing `KESTRIX_HISTORY_KEY` loses every stored report, and nothing else.
- Turning history off is per user and immediate; there is no server-wide switch other than not deploying the feature.

## Alternatives considered

- **Store history in the browser only.** No server data, but nothing follows the user across devices and the owner
  asked for server-side history.
- **Encrypt per user with keys derived from the sign-in.** Stronger against an operator, but a refresh-token based
  key would be lost on every sign-out, and OAuth gives no stable secret to derive from.
- **One table in the accounts database with `ON DELETE CASCADE`.** Simpler deletion, but couples the history to
  the accounts schema check and would not work in local mode, which has no accounts table.
