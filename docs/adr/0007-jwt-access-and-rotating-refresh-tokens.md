# ADR 0007: JWT access tokens and rotating refresh tokens

- Status: accepted
- Date: 2026-10-21
- Decision owner: Ruthvik Bandari
- Amends: [ADR 0004](0004-hosted-mode.md), "Accounts and sessions"

## Context

ADR 0004 gave the hosted service one opaque session cookie, looked up in SQLite on every request. The owner wants
hosted sign-in to use short-lived JWT access tokens with rotating refresh tokens, keeping sign-in with Google or
GitHub, and wants the landing page (`/`) to carry a Log in / Sign up card in its hero.

The service is pre-launch, so no stored sessions have to survive the change.

## Decision

### Access token

- A JWT signed with HS256 under `KESTRIX_JWT_SECRET`, which is required in hosted mode and must be at least 32
  bytes; the server refuses to start without it.
- The header carries a `kid`, a keyed hash of the secret. `KESTRIX_JWT_SECRET_PREVIOUS`, when set, is accepted for
  verification only, so the secret can be rotated without signing everyone out. New tokens always use the current
  key.
- Claims, all required:
  - `iss`, the public origin;
  - `aud`, `kestrix`;
  - `sub`, the internal user id as a string;
  - `sid`, the refresh family's id;
  - `iat`, `nbf` and `exp` (15 minutes);
  - `jti`, a random id.
- Verification pins `algorithms=["HS256"]` (no `none`, no other HMAC sizes, no public-key algorithms), an
  unknown `kid` is invalid, and the time claims allow 30 seconds of leeway.
- Signing and signature checks use PyJWT (MIT), installed only with the `kestrix[hosted]` extra. The time claims
  are checked by Kestrix against the service clock after PyJWT has checked the signature, issuer, audience and
  presence of every claim.
- Cookie `__Host-kx_at`: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=900`.

### Refresh token and family

- An opaque `secrets.token_urlsafe(32)`, stored only as HMAC-SHA256 under `KESTRIX_SESSION_PEPPER`.
- The sessions table becomes the refresh "family": its id (`sid`), the user, the current refresh hash,
  `family_created_at`, `last_used_at`, `expires_at` (30 days after sign-in) and `revoked_at`. A family also ends
  after 7 days without a refresh.
- Hashes of rotated refresh tokens are kept, with the family, until the family is purged, so reuse can be detected.
- Cookie `__Host-kx_rt`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, `Max-Age` up to the family's end. A
  `__Host-` cookie must have `Path=/`, so it cannot be scoped to the refresh route; `SameSite=Strict` and the CSRF
  token cover that.
- **Rotation.** Each `POST /api/auth/refresh` replaces the refresh token and issues a new access token. The
  `sid`, and therefore the CSRF token, stays the same for the whole family.
- **Reuse detection.** Presenting a refresh token that was already rotated revokes the whole family and logs a
  security event with only the salted user tag.

### Endpoints

- `POST /api/auth/refresh`: needs `X-CSRF-Token` for the family, and is rate-limited per IP (60 per 10 minutes).
- The sign-in callback sets both cookies. Signing in again revokes the family named by an existing refresh cookie.
- `POST /api/auth/logout` revokes the family; `DELETE /api/auth/account` deletes the user and every family.
- `GET /api/auth/me` returns the CSRF token and `access_expires_at`. When the access token is missing or expired but
  the refresh cookie names a live family, it answers `{"signed_in": false, "refreshable": true, "csrf_token": ...}`
  so a freshly opened page can refresh without a prior token. It never rotates anything (`GET` has no side effects).

### Immediate revocation

- Every authenticated request verifies the JWT, then checks that its `sid` family is live (not revoked, not expired,
  user not disabled).
- The check is cached in process for 30 seconds. Logout, account deletion and reuse detection update the cache in
  the same process at once.
- Another process (for example `kestrix hosted disable-user`) takes effect within 30 seconds. The service runs as
  one instance today; a second instance would need a shared revocation store.

### 401 reasons

- `token_expired`: the access token has a valid signature but has expired, or it is missing while a refresh cookie is
  present. The client refreshes once and retries.
- `sign_in_required`: no usable token.

### Unchanged

CSRF stays the `X-CSRF-Token` scheme, derived from the `sid` with the server pepper. Rate limits, Host and Origin
checks, HSTS, `no-store`, privacy-safe logs, worker isolation and local mode (no accounts) do not change.

### Sign up and terms

The sign-in start takes `intent=signup` from the landing card's Sign up tab, whose buttons stay disabled until the
visitor agrees to the terms and acknowledges the privacy notice. The intent is stored with the pending sign-in.
A new account created through Sign up records `terms_accepted_at`. A new account created through Log in is sent to
the dashboard with a one-time "account created" note that links to the terms.

### Migration

None: the service has not launched. A database with the ADR 0004 schema is refused at start-up with instructions
to move it aside, as before. The opaque session cookie and its code are removed.

## Consequences

- An access token is checked without a database read most of the time; the 30-second revocation cache bounds how
  stale a check can be.
- Two tabs refreshing with the same token at once would look like reuse. The dashboard serializes refreshes across
  tabs with the Web Locks API, and a lost refresh response signs the user out, the safe failure.
- Operators must set and protect a second secret, `KESTRIX_JWT_SECRET`.
- The privacy notice names the two new cookies and `terms_accepted_at`.
