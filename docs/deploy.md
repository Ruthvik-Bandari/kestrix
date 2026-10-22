# Deploying hosted mode

This guide puts Kestrix hosted mode ([hosted.md](hosted.md), [ADR 0004](adr/0004-hosted-mode.md)) on [Fly.io](https://fly.io) with the repository's `Dockerfile` and `fly.toml`. It is slice H3. Do not open the site to the public until the privacy notice and terms (H4) are reviewed and published and the [go-live checklist](#go-live-checklist) is done. Nothing in this repository deploys, publishes or pushes anything: every step below is run by the owner.

## Contents

- [What you get](#what-you-get)
- [Try the image locally](#try-the-image-locally)
- [Deploy to Fly.io](#deploy-to-flyio)
- [Client IPs and rate limits](#client-ips-and-rate-limits)
- [Backups](#backups)
- [Rotating secrets](#rotating-secrets)
- [Cost](#cost)
- [Preflight](#preflight)
- [Go-live checklist](#go-live-checklist)
- [Why not Render](#why-not-render)

## What you get

| Piece | What it does |
| --- | --- |
| `Dockerfile` | Three stages: Node builds the dashboard, uv builds the wheel and a venv with only the locked runtime dependencies (no dev or gpu groups, no `ai` or `exif` extras), then a `python:3.12-slim` final stage. Every base image is pinned by digest. The wheel is built with `uv build --offline` by the pinned uv binary's own `uv_build` backend, so no build backend is downloaded. |
| `.dockerignore` | An allowlist: only `pyproject.toml`, `uv.lock`, `README.md`, `LICENSE`, `NOTICE`, `src/kestrix/` and `frontend/` reach the build. `src/kestrixbench`, `data/`, `docs/`, `hpc/`, `tests/`, `.git` and any `.env` files never do. |
| `fly.toml` | One machine, a 1 GB volume at `/data` for the SQLite file, HTTPS forced at Fly's edge, and a health check on `/api/health`. |
| CI job `container` | Builds the image (never pushes it), checks that it runs as uid 10001 on a read-only root filesystem and answers `/api/health` in hosted mode, and runs `scripts/deploy_preflight.py --dry-run` inside it. |
| CI job `security` | `kestrix-scan` on Kestrix's own code (blocking), `pip-audit` of the packages the image ships and `npm audit --omit=dev` (both blocking), and audits of the development tools (report only). |
| `scripts/deploy_preflight.py` | The go-live check: secrets, origin, providers, database permissions, the built bundle, headers, health, private-target refusal and rate limits, with PASS or FAIL per item and no secret in the output. See [Preflight](#preflight). |

The image:

- runs `kestrix serve-hosted` as user `kestrix` (uid and gid 10001), with no login shell and no `pip`. No tools are added to the base image (no compiler, `uv`, `npm` or `git`; checked in a built image); its own `/bin/sh` and `apt` are still there, owned by root. Every setuid and setgid bit is removed at build time (none remain);
- sets `KESTRIX_MODE=hosted`, `KESTRIX_DB=/data/kestrix.db`, `KESTRIX_HOME=/data` and `PORT=8000`;
- writes only to `/data` (the database) and `/tmp` (uploads over 1 MiB spill to an anonymous temporary file there while they are analyzed, and the analysis workers' fork server keeps its socket there; nothing is kept);
- runs on a read-only root filesystem when `/tmp` is a tmpfs (as in `docker run` below and the CI job). Fly.io Machines have no read-only-root or tmpfs option: there the root filesystem is the image's, writable but reset on every restart, and `/tmp` is on that disk. The app user can still write only to `/tmp` and `/data`, because everything else belongs to root;
- refuses to start (exit code 2, with a message naming the variable) when the hosted configuration is missing or malformed.

## Try the image locally

```bash
docker build -t kestrix:dev .
docker volume create kestrix-data
docker run --rm --name kestrix \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --cap-drop ALL --security-opt no-new-privileges \
  -v kestrix-data:/data -p 127.0.0.1:8000:8000 \
  -e KESTRIX_PUBLIC_ORIGIN=https://kestrix.test \
  -e KESTRIX_SESSION_PEPPER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e KESTRIX_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e KESTRIX_HISTORY_KEY="$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')" \
  -e KESTRIX_GITHUB_CLIENT_ID=dummy -e KESTRIX_GITHUB_CLIENT_SECRET=dummy \
  kestrix:dev
```

In another terminal:

```bash
curl -s -H 'Host: kestrix.test' http://127.0.0.1:8000/api/health
# {"status":"ok",...,"mode":"hosted","modules":["forensics","webcheck","mail"]}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/health   # 421: wrong Host
```

The server answers only requests whose `Host` is the host of `KESTRIX_PUBLIC_ORIGIN`, so every probe, including health checks, has to send it. Sign-in cannot complete locally with dummy credentials, and the browser will not send the `__Host-` access and refresh cookies over plain `http`. The `/tmp` tmpfs must hold the largest hosted upload (10 MiB plus the multipart framing) for each upload in progress; 128 MB is ample.

The image also has a Docker `HEALTHCHECK` that sends the right `Host`. Fly.io ignores it and uses the checks in `fly.toml`.

## Deploy to Fly.io

### 1. Install flyctl and sign in

```bash
brew install flyctl          # or: curl -L https://fly.io/install.sh | sh
fly auth login
```

### 2. Choose the app name, region and domain

Edit `fly.toml`:

- `app`: a globally unique name, such as `kestrix-yourname`;
- `primary_region`: a region near your users (`fly platform regions`);
- `KESTRIX_PUBLIC_ORIGIN` and the check's `Host` header: your public host. They must agree.

If you have no domain yet, use `https://<app>.fly.dev` as the origin and `<app>.fly.dev` as the check's `Host`. Changing the domain later means updating both values and both OAuth apps' redirect URIs.

### 3. Create the app and the volume

```bash
fly apps create kestrix-yourname
fly volumes create kestrix_data --region iad --size 1 --snapshot-retention 14
```

`fly launch --no-deploy` also works with the existing `fly.toml` (answer yes to copying its configuration), but it may offer to add databases or other services; Kestrix needs none.

Fly warns that a single volume has no redundancy. That is expected: Kestrix runs one machine (see [Backups](#backups)).

### 4. Register the OAuth apps

Follow [hosted.md, "Register the OAuth apps"](hosted.md#register-the-oauth-apps). The redirect URIs are:

- Google: `https://<your host>/api/auth/callback/google`
- GitHub: `https://<your host>/api/auth/callback/github`

You need at least one provider.

### 5. Set the secrets

Secrets live in Fly's secret store and reach the machine as environment variables. Use `--stage` so nothing restarts before the first deploy. `read -rs` keeps each value out of your shell history and off the screen.

```bash
fly secrets set --stage KESTRIX_SESSION_PEPPER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
# Signs the 15-minute access tokens (ADR 0007). A separate value; never reuse the pepper.
fly secrets set --stage KESTRIX_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
# Encrypts users' stored result reports (ADR 0008): exactly 32 random bytes in base64.
fly secrets set --stage KESTRIX_HISTORY_KEY="$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"

read -rs GOOGLE_SECRET            # paste, then Enter
fly secrets set --stage KESTRIX_GOOGLE_CLIENT_ID=<client id> KESTRIX_GOOGLE_CLIENT_SECRET="$GOOGLE_SECRET"
read -rs GITHUB_SECRET
fly secrets set --stage KESTRIX_GITHUB_CLIENT_ID=<client id> KESTRIX_GITHUB_CLIENT_SECRET="$GITHUB_SECRET"
unset GOOGLE_SECRET GITHUB_SECRET

fly secrets set --stage KESTRIX_ABUSE_CONTACT=abuse@<your domain>
# Optional, at least 16 bytes. Without it the log salt is derived from the pepper.
fly secrets set --stage KESTRIX_LOG_SALT="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
fly secrets list                  # names and digests only, never values
```

| Name | Where | Required |
| --- | --- | --- |
| `KESTRIX_SESSION_PEPPER` | secret | Yes |
| `KESTRIX_JWT_SECRET` | secret | Yes |
| `KESTRIX_JWT_SECRET_PREVIOUS` | secret | Only during a rotation (see [Rotating secrets](#rotating-secrets)) |
| `KESTRIX_HISTORY_KEY` | secret | Yes |
| `KESTRIX_HISTORY_KEY_PREVIOUS` | secret | Only during a rotation (see [Rotating secrets](#rotating-secrets)) |
| `KESTRIX_GOOGLE_CLIENT_ID`, `KESTRIX_GOOGLE_CLIENT_SECRET` | secret | One provider (both or neither) |
| `KESTRIX_GITHUB_CLIENT_ID`, `KESTRIX_GITHUB_CLIENT_SECRET` | secret | One provider (both or neither) |
| `KESTRIX_ABUSE_CONTACT` | secret or `[env]` | Recommended: it goes into the website check's `User-Agent` |
| `KESTRIX_LOG_SALT` | secret | No |
| `KESTRIX_PUBLIC_ORIGIN` | `[env]` in `fly.toml` | Yes. It is the public address, not a secret, and sits next to the check's `Host` so the two are edited together. Setting it as a secret instead also works; a secret overrides `[env]`. |
| `KESTRIX_MODE`, `KESTRIX_DB`, `PORT` | `[env]` and the image | Already set |

### 6. Deploy

```bash
fly deploy --ha=false
fly status                         # one machine, state "started"
fly checks list                    # the /api/health check is "passing"
fly logs                           # "Hosted mode on port 8000" and kestrix.access lines
```

`--ha=false` keeps it to one machine. Never run more than one: rate limits are counted per process and SQLite is one file on one volume. If `fly machines list` ever shows two, run `fly scale count 1`.

Check that the volume is writable by the app user:

```bash
fly ssh console -C "ls -ln /data"  # kestrix.db owned by 10001, mode -rw-------
```

If `/data` is owned by root and the logs show a permission error opening the database, run `fly ssh console -C "chown 10001:10001 /data"` once (`fly ssh console` connects as root by default) and restart with `fly machine restart`.

### 7. Custom domain and certificate

```bash
fly ips list                       # Fly allocates a shared IPv4 and an IPv6 address on first deploy
fly certs add kestrix.example.org  # prints the DNS records to create
fly certs check kestrix.example.org
```

Create the records it asks for at your DNS provider (a `CNAME` to `<app>.fly.dev`, or `A`/`AAAA` records), wait for `fly certs check` to report the certificate as issued, then set `KESTRIX_PUBLIC_ORIGIN` and the check's `Host` to the domain and deploy again. After that, `https://<app>.fly.dev` answers 421 because only the public host is allowed, which keeps one canonical address.

### 8. Verify

```bash
curl -s https://kestrix.example.org/api/health      # "mode":"hosted"
curl -sI https://kestrix.example.org/ | grep -i strict-transport-security
curl -s -o /dev/null -w '%{http_code}\n' http://kestrix.example.org/   # 301 to https (force_https)
curl -s -o /dev/null -w '%{http_code}\n' https://kestrix.example.org/api/detect/cases   # 404
```

Then sign in with each provider in a browser, run a website check on a site you own, analyze a small file, sign out, and confirm that `fly logs` shows route templates and a short user hash, never an email, file name, URL or token.

## Client IPs and rate limits

The sign-in limits (20 sign-in starts and 10 callbacks per 10 minutes) are counted per client IP, and per /64 for IPv6. Behind Fly's proxy:

- **Socket peer (the default).** The server sees Fly's proxy as the peer, so every visitor shares one sign-in bucket. Twenty sign-ins in ten minutes from anyone blocks everyone. This is safe against spoofing but will lock out real users once the site has traffic.
- **`KESTRIX_TRUST_PROXY_HEADERS=1` (not recommended on Fly).** Kestrix uses the right-most `X-Forwarded-For` entry. Fly documents the right-most entry as a shared or dedicated IP address assigned to your app, not the client, so this gives no per-client limit. Leave it unset.
- **`KESTRIX_CLIENT_IP_HEADER=Fly-Client-IP` (set in `fly.toml`).** Fly documents this header as the client's IP address as seen by its proxy. Kestrix reads it only when this setting names it. A missing value, a malformed one, or two copies of the header fall back to the socket peer. Fly does not document whether it replaces a `Fly-Client-IP` header sent by the client, so check that once after the first deploy:

  ```bash
  # 21 sign-in starts, each claiming a different client IP. If Fly overwrites the header,
  # they all count against your one real IP and the 21st gets 429. If the 21st is a 302,
  # the header is spoofable: remove KESTRIX_CLIENT_IP_HEADER from fly.toml and redeploy.
  for i in $(seq 1 21); do
    curl -s -o /dev/null -w '%{http_code}\n' -H "Fly-Client-IP: 198.51.100.$i" \
      "https://YOUR_DOMAIN/api/auth/login/github"
  done
  ```

Without `KESTRIX_CLIENT_IP_HEADER` every visitor shares one sign-in bucket; treat that as a launch blocker for anything beyond a small private preview.

`auto_stop_machines = "stop"` in `fly.toml` is the cheapest setting: the machine stops when idle and starts on the next request. Every stop clears the in-memory counters, so a user who waits for the machine to stop gets a fresh hourly allowance. For launch, set `auto_stop_machines = "off"` and `min_machines_running = 1`.

## Backups

The volume holds users, sessions and pending sign-ins (`/data/kestrix.db`) and the encrypted result history (`/data/kestrix-history.db`, ADR 0008). Losing it signs everyone out, forgets accounts and empties every history; nobody's files are on it. A snapshot of the history file is useless without `KESTRIX_HISTORY_KEY`, which is not on the volume.

- **Snapshots.** Fly takes daily volume snapshots, kept for the retention set when the volume was created (14 days with the command in step 3; `snapshot_retention` in `fly.toml` says the same for volumes that `fly deploy` creates). SQLite in WAL mode recovers from a crash-consistent snapshot. A deleted account's row is overwritten in the live database at once, but stays in snapshots taken before the deletion until they expire; the draft privacy notice says so.

  ```bash
  fly volumes list                              # note the volume id
  fly volumes snapshots list <volume id>
  fly volumes snapshots create <volume id>      # on demand, for example before an upgrade
  ```

  To restore, create a volume from a snapshot (`fly volumes create kestrix_data --snapshot-id <snapshot id> --region iad --size 1`), destroy the old volume and machine, and deploy.

- **Off-platform copy.** The database contains users' email addresses. If you copy it out, store it encrypted and delete old copies.

  ```bash
  fly ssh console -C "python -c \"import sqlite3; sqlite3.connect('/data/kestrix.db').backup(sqlite3.connect('/data/backup.db'))\""
  fly sftp get /data/backup.db ./kestrix-backup.db
  fly ssh console -C "rm /data/backup.db"
  ```

## Rotating secrets

`fly secrets set` restarts the machine with the new values.

| Secret | Effect of rotating | How |
| --- | --- | --- |
| `KESTRIX_SESSION_PEPPER` | Everyone is signed out (refresh tokens and CSRF tokens no longer match); pending sign-ins fail. Accounts stay. | Set a new value. Rotate at once if it may have leaked. |
| `KESTRIX_JWT_SECRET` | None if done in order: access tokens signed with the old key keep working until they expire (15 minutes). | `fly secrets set KESTRIX_JWT_SECRET_PREVIOUS=<the current value> KESTRIX_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"`, then after 15 minutes `fly secrets unset KESTRIX_JWT_SECRET_PREVIOUS`. After a suspected leak, skip `KESTRIX_JWT_SECRET_PREVIOUS`: every access token ends at once and pages refresh with their refresh tokens. |
| `KESTRIX_HISTORY_KEY` | None if done in order: reports stored under the old key stay readable through `KESTRIX_HISTORY_KEY_PREVIOUS`. | `fly secrets set KESTRIX_HISTORY_KEY_PREVIOUS=<the current value> KESTRIX_HISTORY_KEY="$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"`, then after 30 days (when the last old report has expired) `fly secrets unset KESTRIX_HISTORY_KEY_PREVIOUS`. After a suspected leak, skip `KESTRIX_HISTORY_KEY_PREVIOUS`: older reports become unreadable and disappear from users' views, and are purged within 30 days. |
| `KESTRIX_LOG_SALT` | User hashes in new log lines no longer match older lines. | Set a new value. |
| OAuth client secret | None if done in order. | Create a second secret at the provider, set it, confirm a sign-in works, then delete the old one at the provider. |
| Any secret after a suspected leak | | Rotate it, then `fly secrets list` to confirm the digest changed, and review `fly logs` for `kestrix.auth` failures. |

## Cost

Fly.io's free allowances and prices change. Check [fly.io/pricing](https://fly.io/pricing) before you deploy. The things that cost money in this setup are the machine (`shared-cpu-1x`, 512 MB; less is not enough since analyses run in their own worker processes, see the measurement below), the 1 GB volume and its snapshots, outbound data, and a dedicated IPv4 address if you add one (the default shared IPv4 is enough for HTTPS). Keeping the machine always on (`min_machines_running = 1`) costs more than letting it stop when idle. Set a spending limit or billing alert in the Fly dashboard.

In a local test (Docker, `/tmp` on tmpfs), the idle container used about 120 MiB: the server, the analysis fork server and multiprocessing's resource tracker. Four users each sending a worst-case 9.9 MiB email at once, three times over, peaked at 377 MiB for the whole container: two analyses ran (each worker peaked near 170 MiB RSS, about 70 MiB of it shared with the fork server) and the rest got 503 `busy`. That fits 512 MB; 256 MB does not.

## Preflight

`scripts/deploy_preflight.py` checks a target before it takes traffic. It runs the real application in process with a temporary database and a fake session, so it never writes to your database, never contacts a provider and never sends a request to a website. It prints `PASS`, `FAIL`, `WARN` or `SKIP` per item and exits 1 if anything failed. It never prints a secret value: it reports lengths and reasons, and it scrubs every secret it knows from its own output.

```bash
uv run python scripts/deploy_preflight.py --dry-run            # throwaway config; what CI runs
uv run python scripts/deploy_preflight.py --env-file staging.env   # a 0600 KEY=VALUE file, or the exported environment
uv run python scripts/deploy_preflight.py --url https://staging.kestrix.example.org   # also two GETs to a live site
# Against a container, with its real environment (nothing leaves the container; tested with the CI image):
docker exec -i <container> python - < scripts/deploy_preflight.py
# On a Fly machine (the image has no scripts/ folder, so copy the script in first; flyctl commands not run here):
fly ssh sftp shell      # then: put scripts/deploy_preflight.py /tmp/deploy_preflight.py
fly ssh console -C "python /tmp/deploy_preflight.py"
```

What it checks:

| Item | Passes when |
| --- | --- |
| `KESTRIX_JWT_SECRET`, `KESTRIX_SESSION_PEPPER` | at least 32 bytes, at least 12 distinct characters, at least 3 bits of entropy per character, and not a placeholder (a word such as `example`, `secret`, `test`, `changeme`) |
| `KESTRIX_HISTORY_KEY` | base64 of exactly 32 bytes with at least 16 distinct byte values |
| `secrets-distinct` | the three secrets differ |
| `KESTRIX_PUBLIC_ORIGIN` | `https://host`, no path, and the host is not `localhost`, an IP address, or a reserved name such as `.example`, `.test`, `.invalid` |
| `oauth-google`, `oauth-github`, `oauth-any` | each configured provider has both id and a secret of at least 16 characters; at least one is complete (one missing provider is a warning) |
| `KESTRIX_ABUSE_CONTACT` | an email address or https URL that is not a reserved name |
| `client-ip` | `KESTRIX_CLIENT_IP_HEADER` or `KESTRIX_TRUST_PROXY_HEADERS` is set, so per-address limits do not all count the proxy |
| `db-dir`, `db-mode:*` | the database folder is writable; any existing database file is mode 0600 |
| `bundle` | `index.html` references only content-hashed files that exist, with no inline script, style or event handler |
| `settings`, `health`, `host-allowlist`, `auth-gate` | the server would start with this configuration, `/api/health` reports hosted mode, a foreign `Host` gets 421, and a signed-out `/api/webcheck` gets 401 |
| `headers:*`, `cache:*` | CSP (script-src `'self'`, no unsafe-inline/eval, object-src, base-uri and frame-ancestors `'none'`), HSTS of a year or more with `includeSubDomains`, nosniff, COOP and CORP `same-origin`, Referrer-Policy, Permissions-Policy; `/api/` is `no-store`, `index.html` is `no-cache` |
| `private-targets` | webcheck refuses loopback, link-local, private and `localhost` targets (403 `target_not_allowed`) |
| `rate-limits:*` | per-user and per-address limits are defined, and the 21st sign-in start from one address gets 429 |
| `hsts-preload` | a warning when `KESTRIX_HSTS_PRELOAD=1`, so the owner confirms it on purpose |

Sample (the production image started with CI's placeholder values, so it correctly says NOT READY; secrets never appear):

```text
PASS KESTRIX_JWT_SECRET          set, 64 bytes, not a placeholder
PASS KESTRIX_HISTORY_KEY         set, 32 bytes of base64
FAIL KESTRIX_PUBLIC_ORIGIN       kestrix.ci.invalid is a local, reserved or IP-literal name, not a public host
FAIL oauth-github                client secret is too short or a placeholder
FAIL client-ip                   neither KESTRIX_CLIENT_IP_HEADER nor KESTRIX_TRUST_PROXY_HEADERS is set; ...
PASS headers:page                CSP, HSTS, COOP, CORP, nosniff, Referrer-Policy and Permissions-Policy are correct
PASS private-targets             5 loopback, link-local and private targets -> [(403, 'target_not_allowed')]
PASS rate-limits:enforced        sign-in start: request 21 -> 429 (want 429 after 20)

22 passed, 4 failed, 1 warnings, 0 skipped: NOT READY
```

It does not replace the manual items below: it cannot see DNS, the certificate on the live host, the OAuth consoles, your backups or your mailbox.

## Go-live checklist

Items marked **[OWNER]** can only be done by the person who owns the domain, the cloud account, the OAuth consoles or the legal responsibility; the code and CI cannot do them for you. Do them in order.

### 1. Before the first public request

- [ ] **[OWNER] Legal pages.** `docs/legal/privacy-draft.md` and `terms-draft.md` are drafts, not legal advice. The owner (and, if possible, a lawyer) must review them, check them against what the service really does (email and display name kept; uploads never stored; reports kept 30 days, encrypted; logs; backups that keep a deleted account until snapshots expire), set the real contact, and only then publish them as the site's `/privacy` and `/terms`. Do not launch with the word "draft" on them.
- [ ] **[OWNER] DNS and TLS.** Point the domain at Fly (`fly certs add`, then the `CNAME` or `A`/`AAAA` records), wait for `fly certs check` to report the certificate issued, and confirm `https://<domain>/` loads with a valid chain. Set `KESTRIX_PUBLIC_ORIGIN` and the health check's `Host` to the domain, then redeploy. `https://<app>.fly.dev` must now answer 421.
- [ ] **[OWNER] OAuth redirect URIs.** Google: `https://<domain>/api/auth/callback/google`, with the consent screen published (not in testing) and test users removed. GitHub: `https://<domain>/api/auth/callback/github`. Remove any localhost or staging redirect URI from the production apps. Use separate OAuth apps for staging.
- [ ] **[OWNER] Secrets.** Generate three different production secrets and never reuse them from staging or this repository (commands in [Set the secrets](#5-set-the-secrets)): the session pepper and the JWT secret (`secrets.token_urlsafe(48)`) and the history key (32 random bytes in base64). Store them in Fly's secret store and in a password manager; leave `KESTRIX_JWT_SECRET_PREVIOUS` and `KESTRIX_HISTORY_KEY_PREVIOUS` unset.
- [ ] **[OWNER] Abuse contact.** `KESTRIX_ABUSE_CONTACT` is a mailbox you read. Website checks send it in their `User-Agent`, and operators of checked sites will write to it. Decide how you answer a report (`kestrix hosted hash-host`, `disable-user`; see [hosted.md](hosted.md#abuse-handling)). Consider publishing the same address in `SECURITY.md` and a `/.well-known/security.txt`.
- [ ] **Rate limits.** `KESTRIX_CLIENT_IP_HEADER=Fly-Client-IP` is set and the spoofing check in [Client IPs and rate limits](#client-ips-and-rate-limits) passes (the 21st forged request gets 429). `auto_stop_machines = "off"` and `min_machines_running = 1` so the limits are not reset by idle stops. Exactly one machine.
- [ ] **HSTS preload is an owner decision.** The server sends `max-age=63072000; includeSubDomains` and not `preload`. **[OWNER]** Add `KESTRIX_HSTS_PRELOAD=1` and submit to [hstspreload.org](https://hstspreload.org) only if the registrable domain and every present and future subdomain will always serve HTTPS; removal takes months. A subdomain-only deployment cannot be preloaded.
- [ ] **Image and dependencies.** CI is green, including `container` and `security`. The base image digests in the `Dockerfile` are recent (`docker buildx imagetools inspect python:3.12-slim`), and `docker scout quickview` or another scanner shows no fixable critical or high issues.

### 2. Staging run

- [ ] **[OWNER] Deploy a staging app** (a second Fly app, its own volume, its own OAuth apps and secrets, a `*.fly.dev` or staging host). The same image as production.
- [ ] Run the preflight against it, with its real environment, and fix every `FAIL`:

  ```bash
  # In the machine, reading its environment (copy the script first, see Preflight):
  fly ssh console -C "python /tmp/deploy_preflight.py"
  # From your computer, adds the live header probe:
  uv run python scripts/deploy_preflight.py --dry-run --url https://<staging host>
  ```

- [ ] Self-scan the staging site with Kestrix's own website check, whole site, from your computer (the target is public, so no `--allow-private`):

  ```bash
  uv run kestrix webcheck scan https://<staging host>
  ```

  Expect grade A. The only finding that may remain is the informational `hsts.not_preload_ready`, which is the preload decision above. Anything else is a regression: fix it before launch. The scan sees the signed-out pages; cookie flags are checked by `tests/server/test_site_hardening.py`, and you confirm them by hand in the browser's storage panel (`__Host-` prefix, `Secure`, `HttpOnly`, `SameSite`).
- [ ] In a browser, with each provider: sign in, run a website check on a site you own, analyze a small file and a saved email, open Recent results, sign out, sign in again, delete the account. The browser console shows no Content-Security-Policy violation.
- [ ] `fly logs` shows route templates and short hashes, never an email, file name, URL, cookie or token.

### 3. Operate

- [ ] **Monitoring of `/api/health`.** Fly's check (`fly checks list`) restarts a failed machine. **[OWNER]** Add an external monitor from outside Fly (an uptime service or a scheduled job) that requests `https://<domain>/api/health` every minute and pages you on a non-200 response or a missing `"mode":"hosted"`. Also alert on the certificate's expiry date (Fly renews it; the alert catches a failed renewal) and on a Fly billing limit.
- [ ] **Log retention.** The app writes to stdout only: `kestrix.access` (method, route template, status, duration, salted user hash), `kestrix.auth` and `kestrix.webcheck`. They hold no personal data, but they do show behavior, so keep them as short as your abuse process needs. Fly keeps only recent logs; **[OWNER]** if you want more, add a Fly log shipper to a store you control, set its retention (30 days is enough to answer an abuse report), and say so in the privacy notice. Do not log request bodies at any layer.
- [ ] **Backups.** Volume snapshots run daily with 14 days kept (see [Backups](#backups)); take one before each upgrade and **test a restore into a staging volume once**. **[OWNER]** Store the three secrets in a password manager now: a restored `kestrix-history.db` is unreadable without `KESTRIX_HISTORY_KEY`, and losing the key loses every stored report (accounts still work). Never put the key in the same place as a database copy. An off-platform database copy holds email addresses: encrypt it and delete old copies.
- [ ] **Rotations and incidents.** You know the rotation steps ([Rotating secrets](#rotating-secrets)) and who can run them. After a suspected leak, rotate without the `*_PREVIOUS` value.
- [ ] **Dependencies.** CI fails on a new advisory in the shipped packages. Re-run `uv lock --upgrade-package <name>` and redeploy; subscribe to GitHub security alerts for the repository.

### 4. Go live and roll back

- [ ] **[OWNER]** Deploy production with the same image that passed staging: `fly deploy --ha=false`. Run the preflight in the production machine (`fly ssh console -C "python /tmp/deploy_preflight.py"`) and the live probe from your computer (`--dry-run --url https://<domain>`), then the checks in [Verify](#8-verify). Announce only after both pass.
- [ ] **Rollback.** Before every deploy note the current release (`fly releases`, `fly image show`). To roll back, deploy the previous image: `fly deploy --image <previous image reference> --ha=false` (or `fly machine update <id> --image <previous>`). The database schema is checked at start and refuses an older schema, so a rollback across a schema change needs the matching volume snapshot: restore it first (see [Backups](#backups)). If sign-in itself is the problem, put the site in maintenance by scaling to zero (`fly scale count 0`) rather than leaving a half-working service up; `fly scale count 1` brings it back.
- [ ] After launch, watch `fly logs` and the external monitor for the first day; check the abuse mailbox daily for the first week.

## Why not Render

Render's free web services have no persistent disk, so the SQLite file (users and sessions) would be lost on every restart or deploy, and they sleep when idle, which also resets the in-memory rate limits. A paid Render instance with a disk would work with the same image; there is no `render.yaml` here.
