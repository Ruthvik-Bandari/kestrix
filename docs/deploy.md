# Deploying hosted mode

This guide puts Kestrix hosted mode ([hosted.md](hosted.md), [ADR 0004](adr/0004-hosted-mode.md)) on [Fly.io](https://fly.io) with the repository's `Dockerfile` and `fly.toml`. It is slice H3. Do not open the site to the public until the privacy notice and terms (H4) are published and the [launch checklist](#before-launch) is done.

## Contents

- [What you get](#what-you-get)
- [Try the image locally](#try-the-image-locally)
- [Deploy to Fly.io](#deploy-to-flyio)
- [Client IPs and rate limits](#client-ips-and-rate-limits)
- [Backups](#backups)
- [Rotating secrets](#rotating-secrets)
- [Cost](#cost)
- [Before launch](#before-launch)
- [Why not Render](#why-not-render)

## What you get

| Piece | What it does |
| --- | --- |
| `Dockerfile` | Three stages: Node builds the dashboard, uv builds the wheel and a venv with only the locked runtime dependencies (no dev or gpu groups, no `ai` or `exif` extras), then a `python:3.12-slim` final stage. Every base image is pinned by digest. |
| `.dockerignore` | An allowlist: only `pyproject.toml`, `uv.lock`, `README.md`, `LICENSE`, `NOTICE`, `src/kestrix/` and `frontend/` reach the build. `src/kestrixbench`, `data/`, `docs/`, `hpc/`, `tests/`, `.git` and any `.env` files never do. |
| `fly.toml` | One machine, a 1 GB volume at `/data` for the SQLite file, HTTPS forced at Fly's edge, and a health check on `/api/health`. |
| CI job `container` | Builds the image (never pushes it) and checks that it runs as uid 10001 on a read-only root filesystem and answers `/api/health` in hosted mode. |

The image:

- runs `kestrix serve-hosted` as user `kestrix` (uid and gid 10001), with no login shell and no `pip`;
- sets `KESTRIX_MODE=hosted`, `KESTRIX_DB=/data/kestrix.db`, `KESTRIX_HOME=/data` and `PORT=8000`;
- writes only to `/data` (the database) and `/tmp` (uploads over 1 MiB spill to an anonymous temporary file there while they are analyzed; nothing is kept);
- runs on a read-only root filesystem when `/tmp` is a tmpfs;
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
  -e KESTRIX_GITHUB_CLIENT_ID=dummy -e KESTRIX_GITHUB_CLIENT_SECRET=dummy \
  kestrix:dev
```

In another terminal:

```bash
curl -s -H 'Host: kestrix.test' http://127.0.0.1:8000/api/health
# {"status":"ok",...,"mode":"hosted","modules":["forensics","webcheck","mail"]}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/health   # 421: wrong Host
```

The server answers only requests whose `Host` is the host of `KESTRIX_PUBLIC_ORIGIN`, so every probe, including health checks, has to send it. Sign-in cannot complete locally with dummy credentials, and the browser will not send the `__Host-` session cookie over plain `http`. The `/tmp` tmpfs must hold the largest upload (about 51 MB) times the number of concurrent uploads.

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

The sign-in limits (10 per 10 minutes) are counted per client IP. Behind Fly's proxy:

- **Socket peer (the default).** The server sees Fly's proxy as the peer, so every visitor shares one sign-in bucket. Ten sign-ins in ten minutes from anyone blocks everyone. This is safe against spoofing but will lock out real users once the site has traffic.
- **`KESTRIX_TRUST_PROXY_HEADERS=1` (not recommended on Fly).** Kestrix uses the right-most `X-Forwarded-For` entry. Fly documents the right-most entry as a shared or dedicated IP address assigned to your app, not the client, so this gives no per-client limit. Leave it unset.
- **`KESTRIX_CLIENT_IP_HEADER=Fly-Client-IP` (set in `fly.toml`).** Fly documents this header as the client's IP address as seen by its proxy. Kestrix reads it only when this setting names it. A missing value, a malformed one, or two copies of the header fall back to the socket peer. Fly does not document whether it replaces a `Fly-Client-IP` header sent by the client, so check that once after the first deploy:

  ```bash
  # 11 sign-in starts, each claiming a different client IP. If Fly overwrites the header,
  # they all count against your one real IP and the 11th gets 429. If the 11th is a 302,
  # the header is spoofable: remove KESTRIX_CLIENT_IP_HEADER from fly.toml and redeploy.
  for i in $(seq 1 11); do
    curl -s -o /dev/null -w '%{http_code}\n' -H "Fly-Client-IP: 198.51.100.$i" \
      "https://YOUR_DOMAIN/api/auth/login/github"
  done
  ```

Without `KESTRIX_CLIENT_IP_HEADER` every visitor shares one sign-in bucket; treat that as a launch blocker for anything beyond a small private preview.

`auto_stop_machines = "stop"` in `fly.toml` is the cheapest setting: the machine stops when idle and starts on the next request. Every stop clears the in-memory counters, so a user who waits for the machine to stop gets a fresh hourly allowance. For launch, set `auto_stop_machines = "off"` and `min_machines_running = 1`.

## Backups

The volume holds users, sessions and pending sign-ins. Losing it signs everyone out and forgets accounts; nobody's files are on it.

- **Snapshots.** Fly takes daily volume snapshots, kept for the retention set when the volume was created (14 days with the command in step 3; `snapshot_retention` in `fly.toml` says the same for volumes that `fly deploy` creates). SQLite in WAL mode recovers from a crash-consistent snapshot.

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
| `KESTRIX_SESSION_PEPPER` | Everyone is signed out; pending sign-ins fail. Accounts stay. | Set a new value. Rotate at once if it may have leaked. |
| `KESTRIX_LOG_SALT` | User hashes in new log lines no longer match older lines. | Set a new value. |
| OAuth client secret | None if done in order. | Create a second secret at the provider, set it, confirm a sign-in works, then delete the old one at the provider. |
| Any secret after a suspected leak | | Rotate it, then `fly secrets list` to confirm the digest changed, and review `fly logs` for `kestrix.auth` failures. |

## Cost

Fly.io's free allowances and prices change. Check [fly.io/pricing](https://fly.io/pricing) before you deploy. The things that cost money in this setup are the machine (`shared-cpu-1x`, 512 MB; 256 MB is possible, see the comment in `fly.toml`), the 1 GB volume and its snapshots, outbound data, and a dedicated IPv4 address if you add one (the default shared IPv4 is enough for HTTPS). Keeping the machine always on (`min_machines_running = 1`) costs more than letting it stop when idle. Set a spending limit or billing alert in the Fly dashboard.

In a local test, the idle container used about 70 MiB, and one 50 MB upload peaked near 125 MiB with `/tmp` on tmpfs.

## Before launch

- [ ] Privacy notice and terms (ADR 0004 slice H4) are published and linked from the site.
- [ ] The `Fly-Client-IP` spoofing check passes (the 11th forged request gets 429; see [Client IPs and rate limits](#client-ips-and-rate-limits)).
- [ ] `auto_stop_machines = "off"` and `min_machines_running = 1`, so rate limits are not reset by idle stops.
- [ ] Exactly one machine (`fly machines list`).
- [ ] Both OAuth apps use the production redirect URIs; the Google consent screen is published; test users removed.
- [ ] `KESTRIX_SESSION_PEPPER` was generated for production and has never been used elsewhere.
- [ ] `KESTRIX_ABUSE_CONTACT` is a monitored mailbox.
- [ ] `fly checks list` passes and `/api/health` reports `"mode":"hosted"` over HTTPS.
- [ ] `http://` redirects to `https://`, and `https://<app>.fly.dev` answers 421 once a custom domain is set.
- [ ] Logs show no emails, file names, URLs, cookies or tokens after a full sign-in and analysis.
- [ ] A volume snapshot exists and you have tested restoring one.
- [ ] CI is green, including the `container` job and the dependency audits.
- [ ] The base image digests in the `Dockerfile` are recent (`docker buildx imagetools inspect python:3.12-slim`), and `docker scout quickview` or another scanner shows no fixable critical or high issues.
- [ ] HSTS preload: the server already sends `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. Submit the domain to [hstspreload.org](https://hstspreload.org) only after confirming that the registrable domain and every subdomain serve HTTPS, because preloading applies to all of them and is slow to undo. Preloading needs the apex domain itself to send the header, so a subdomain-only deployment cannot be preloaded on its own.

## Why not Render

Render's free web services have no persistent disk, so the SQLite file (users and sessions) would be lost on every restart or deploy, and they sleep when idle, which also resets the in-memory rate limits. A paid Render instance with a disk would work with the same image; there is no `render.yaml` here.
