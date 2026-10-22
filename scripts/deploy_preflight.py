#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Go-live preflight for the hosted Kestrix service (docs/deploy.md, "Go-live checklist").

Checks a target environment before it takes traffic, without deploying anything and without
printing a secret value. Each item prints PASS, FAIL, WARN or SKIP; the exit code is 1 when any
item FAILs, 2 for a usage error, else 0.

    uv run python scripts/deploy_preflight.py                  # the real environment (staging or production)
    uv run python scripts/deploy_preflight.py --env-file staging.env
    uv run python scripts/deploy_preflight.py --dry-run        # throwaway configuration, for CI
    uv run python scripts/deploy_preflight.py --url https://kestrix.example.org   # also probe a live site

It runs the real application in process (no network, a temporary database, a fake session), so it
never writes to the production database and never contacts a provider or a website. The optional
``--url`` probe sends two GET requests to the named site.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import json
import math
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
SECRET_VARS = (
    "KESTRIX_JWT_SECRET",
    "KESTRIX_SESSION_PEPPER",
    "KESTRIX_HISTORY_KEY",
    "KESTRIX_LOG_SALT",
    "KESTRIX_JWT_SECRET_PREVIOUS",
    "KESTRIX_HISTORY_KEY_PREVIOUS",
    "KESTRIX_GOOGLE_CLIENT_SECRET",
    "KESTRIX_GITHUB_CLIENT_SECRET",
)
MIN_SECRET_BYTES = 32
MIN_ENTROPY_BITS_PER_CHAR = 3.0  # base64 and hex of random bytes score 4 to 6; words and patterns score under 3
MIN_DISTINCT_CHARS = 12
PLACEHOLDER = re.compile(
    r"change.?me|placeholder|example|your[-_ ]|secret|password|xxxx|0000|1234|test|dummy|todo", re.I
)
RESERVED_HOST = re.compile(
    r"(^|\.)(localhost|local|invalid|test|example|internal|lan)$|^\d{1,3}(\.\d{1,3}){3}$|^\[", re.I
)
HASHED_ASSET = re.compile(r".+-[A-Za-z0-9_-]{8,}\.(js|css|woff2?|svg|png|webp)$")
LOCAL_TARGETS = (
    "https://127.0.0.1/",
    "https://[::1]/",
    "http://169.254.169.254/",
    "https://10.0.0.1/",
    "https://localhost/",
)


@dataclasses.dataclass
class Item:
    id: str
    status: str
    message: str


class Report:
    def __init__(self, secrets_in_play: list[str]) -> None:
        self.items: list[Item] = []
        self._secrets = sorted({s for s in secrets_in_play if len(s) >= 6}, key=len, reverse=True)

    def add(self, id: str, status: str, message: str) -> None:
        self.items.append(Item(id, status, self.redact(message)))

    def redact(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "[redacted]")
        return text

    @property
    def failed(self) -> bool:
        return any(i.status == FAIL for i in self.items)

    def counts(self) -> dict[str, int]:
        counted = Counter(i.status for i in self.items)
        return {status: counted.get(status, 0) for status in (PASS, FAIL, WARN, SKIP)}


def entropy_bits_per_char(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def weak_secret(value: str) -> str | None:
    """Why this secret is weak, or None. Never includes the value."""
    if len(value.encode()) < MIN_SECRET_BYTES:
        return f"{len(value.encode())} bytes, need at least {MIN_SECRET_BYTES}"
    if len(set(value)) < MIN_DISTINCT_CHARS:
        return f"only {len(set(value))} distinct characters, need {MIN_DISTINCT_CHARS}"
    if entropy_bits_per_char(value) < MIN_ENTROPY_BITS_PER_CHAR:
        return f"low entropy ({entropy_bits_per_char(value):.1f} bits per character, need {MIN_ENTROPY_BITS_PER_CHAR})"
    if PLACEHOLDER.search(value):
        return "looks like a placeholder (contains a word such as example, secret or test)"
    return None


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def dry_run_env(workdir: Path) -> dict[str, str]:
    """A complete throwaway configuration: random secrets, a reserved host, a temporary database."""
    return {
        "KESTRIX_MODE": "hosted",
        "KESTRIX_PUBLIC_ORIGIN": "https://preflight.kestrix.invalid",
        "KESTRIX_SESSION_PEPPER": secrets.token_urlsafe(48),
        "KESTRIX_JWT_SECRET": secrets.token_urlsafe(48),
        "KESTRIX_HISTORY_KEY": base64.b64encode(os.urandom(32)).decode(),
        "KESTRIX_DB": str(workdir / "state" / "kestrix.db"),
        "KESTRIX_GOOGLE_CLIENT_ID": "dry-run-google-id",
        "KESTRIX_GOOGLE_CLIENT_SECRET": secrets.token_urlsafe(24),
        "KESTRIX_GITHUB_CLIENT_ID": "dry-run-github-id",
        "KESTRIX_GITHUB_CLIENT_SECRET": secrets.token_urlsafe(24),
        "KESTRIX_ABUSE_CONTACT": "abuse@preflight.kestrix.invalid",
        "KESTRIX_CLIENT_IP_HEADER": "Fly-Client-IP",
    }


# Configuration checks ------------------------------------------------------------------------------


def check_secrets(env: Mapping[str, str], report: Report) -> None:
    values: dict[str, str] = {}
    for name in ("KESTRIX_JWT_SECRET", "KESTRIX_SESSION_PEPPER"):
        value = env.get(name, "")
        if not value:
            report.add(name, FAIL, "not set")
            continue
        problem = weak_secret(value)
        report.add(name, FAIL if problem else PASS, problem or f"set, {len(value.encode())} bytes, not a placeholder")
        values[name] = value
    key = env.get("KESTRIX_HISTORY_KEY", "")
    if not key:
        report.add("KESTRIX_HISTORY_KEY", FAIL, "not set")
    else:
        try:
            raw = base64.b64decode(key, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        if len(raw) != 32:
            report.add("KESTRIX_HISTORY_KEY", FAIL, "must be exactly 32 random bytes in base64")
        elif len(set(raw)) < 16:
            report.add("KESTRIX_HISTORY_KEY", FAIL, "the key bytes are not random (too few distinct values)")
        else:
            report.add("KESTRIX_HISTORY_KEY", PASS, "set, 32 bytes of base64")
        values["KESTRIX_HISTORY_KEY"] = key
    if len(set(values.values())) < len(values):
        report.add("secrets-distinct", FAIL, "two of the three secrets are the same value; each needs its own")
    elif len(values) == 3:
        report.add("secrets-distinct", PASS, "the JWT secret, session pepper and history key are different")
    else:
        report.add("secrets-distinct", SKIP, "a secret is missing")


def check_origin(env: Mapping[str, str], report: Report, *, dry_run: bool) -> None:
    origin = env.get("KESTRIX_PUBLIC_ORIGIN", "").strip()
    if not origin:
        report.add("KESTRIX_PUBLIC_ORIGIN", FAIL, "not set")
        return
    parts = urlsplit(origin)
    if parts.scheme != "https" or not parts.hostname or parts.path not in {"", "/"} or parts.query or parts.fragment:
        report.add("KESTRIX_PUBLIC_ORIGIN", FAIL, "must be https://host with no path (the browser-facing address)")
    elif RESERVED_HOST.search(parts.hostname) and not dry_run:
        report.add(
            "KESTRIX_PUBLIC_ORIGIN",
            FAIL,
            f"{parts.hostname} is a local, reserved or IP-literal name, not a public host",
        )
    else:
        report.add(
            "KESTRIX_PUBLIC_ORIGIN", PASS, f"https origin, host {parts.hostname}" + (" (dry run)" if dry_run else "")
        )
    preload = env.get("KESTRIX_HSTS_PRELOAD", "").strip().lower() in {"1", "true", "yes"}
    report.add(
        "hsts-preload",
        WARN if preload else PASS,
        "HSTS preload is on: submit only after every subdomain serves https (owner decision)"
        if preload
        else "HSTS preload is off (owner choice, docs/deploy.md)",
    )


def check_oauth(env: Mapping[str, str], report: Report) -> None:
    complete = []
    for name in ("GOOGLE", "GITHUB"):
        client_id, client_secret = (
            env.get(f"KESTRIX_{name}_CLIENT_ID", ""),
            env.get(f"KESTRIX_{name}_CLIENT_SECRET", ""),
        )
        if client_id and client_secret:
            weak = len(client_secret) < 16 or PLACEHOLDER.search(client_secret)
            report.add(
                f"oauth-{name.lower()}",
                FAIL if weak else PASS,
                "client secret is too short or a placeholder" if weak else "client id and secret set",
            )
            complete.append(name)
        elif client_id or client_secret:
            report.add(f"oauth-{name.lower()}", FAIL, "only one of the client id and secret is set")
        else:
            report.add(f"oauth-{name.lower()}", WARN, "not configured; users cannot sign in with this provider")
    if not complete:
        report.add("oauth-any", FAIL, "no sign-in provider is configured")


def check_operations(env: Mapping[str, str], report: Report, *, dry_run: bool) -> None:
    contact = env.get("KESTRIX_ABUSE_CONTACT", "").strip()
    if not contact:
        report.add("KESTRIX_ABUSE_CONTACT", FAIL, "not set; website checks must name a contact in their User-Agent")
    elif not ("@" in contact or contact.startswith("https://")) or (
        RESERVED_HOST.search(contact.rsplit("@", 1)[-1].split("/")[0].lower()) and not dry_run
    ):
        report.add("KESTRIX_ABUSE_CONTACT", FAIL, "must be a monitored email address or https URL, not a placeholder")
    else:
        report.add("KESTRIX_ABUSE_CONTACT", PASS, "set (confirm the mailbox is monitored: owner task)")
    header, trust = env.get("KESTRIX_CLIENT_IP_HEADER", "").strip(), env.get("KESTRIX_TRUST_PROXY_HEADERS", "").strip()
    if header or trust.lower() in {"1", "true", "yes"}:
        report.add(
            "client-ip",
            PASS,
            "client address source configured: " + (f"header {header}" if header else "trusted proxy headers"),
        )
    else:
        report.add(
            "client-ip",
            FAIL,
            "neither KESTRIX_CLIENT_IP_HEADER nor KESTRIX_TRUST_PROXY_HEADERS is set; behind a proxy every user shares one rate-limit address",
        )
    check_rate_limit_store(env, report)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        report.add("non-root", WARN, "running as root; the container runs as uid 10001")
    else:
        report.add("non-root", PASS, "not running as root")


def check_rate_limit_store(env: Mapping[str, str], report: Report) -> None:
    """Rate limits are per process unless ``KESTRIX_RATE_LIMIT_STORE=sqlite``; warn when several workers share the limit."""
    store = env.get("KESTRIX_RATE_LIMIT_STORE", "").strip().lower() or "memory"
    workers_value = env.get("WEB_CONCURRENCY", "").strip()
    workers = int(workers_value) if workers_value.isdigit() else 1
    if store not in {"memory", "sqlite"}:
        report.add("rate-limit-store", FAIL, "KESTRIX_RATE_LIMIT_STORE must be memory or sqlite")
    elif workers > 1 and store == "memory":
        report.add(
            "rate-limit-store",
            WARN,
            f"WEB_CONCURRENCY={workers} but rate limits are per process, so each limit is multiplied by {workers}; "
            "set KESTRIX_RATE_LIMIT_STORE=sqlite (docs/hosted.md, Limitations)",
        )
    elif workers > 1:
        report.add(
            "rate-limit-store",
            WARN,
            f"WEB_CONCURRENCY={workers}: rate limits are shared through SQLite, but the per-user busy slot, the "
            "concurrency caps and the 30-second revocation cache stay per process",
        )
    elif store == "sqlite":
        report.add("rate-limit-store", PASS, "rate limits are kept in a shared SQLite file")
    else:
        report.add("rate-limit-store", PASS, "rate limits are kept in this process (one worker)")


def check_database(db_path: Path, report: Report, *, dry_run: bool) -> None:
    parent = db_path.parent
    if parent.is_dir():
        mode = stat.S_IMODE(parent.stat().st_mode)
        writable = os.access(parent, os.W_OK | os.X_OK)
        report.add(
            "db-dir",
            PASS if writable else FAIL,
            f"{parent} is {'writable' if writable else 'NOT writable'}, mode {mode:04o}",
        )
        if mode & 0o077 and not dry_run:
            report.add(
                "db-dir-mode",
                WARN,
                f"{parent} is group or world accessible (mode {mode:04o}); the service tightens it to 0700 at start",
            )
    else:
        existing = next((p for p in parent.parents if p.exists()), None)
        ok = existing is not None and os.access(existing, os.W_OK | os.X_OK)
        report.add(
            "db-dir",
            PASS if ok else FAIL,
            f"{parent} does not exist yet; " + ("it can be created" if ok else "no writable ancestor to create it in"),
        )
    for path in (db_path, db_path.with_name(f"{db_path.stem}-history{db_path.suffix}")):
        if path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            report.add(
                f"db-mode:{path.name}",
                PASS if mode & 0o077 == 0 else FAIL,
                f"mode {mode:04o}" + ("" if mode & 0o077 == 0 else ", must be 0600"),
            )
        else:
            report.add(f"db-mode:{path.name}", SKIP, "not created yet; the service creates it 0600 at first start")


def check_bundle(static_dir: Path, report: Report) -> None:
    index = static_dir / "index.html"
    if not index.is_file():
        report.add("bundle", FAIL, f"{index} is missing; build it with npm --prefix frontend run build")
        return
    page = index.read_text(errors="replace")
    refs = re.findall(r'(?:src|href)="(/assets/[^"]+)"', page)
    unhashed = [r for r in refs if not HASHED_ASSET.match(r)]
    missing = [r for r in refs if not (static_dir / r.lstrip("/")).is_file()]
    inline = (
        bool(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", page))
        or "<style" in page
        or bool(re.search(r"\son[a-z]+\s*=|\sstyle=", page))
    )
    if not refs:
        report.add("bundle", FAIL, "index.html references no /assets/ files")
    elif unhashed or missing or inline:
        why = (
            [f"{len(unhashed)} unhashed asset(s)"] * bool(unhashed)
            + [f"{len(missing)} referenced file(s) missing"] * bool(missing)
            + ["inline script, style or handler (breaks the CSP)"] * inline
        )
        report.add("bundle", FAIL, "; ".join(why))
    else:
        report.add("bundle", PASS, f"index.html and {len(refs)} content-hashed assets, no inline code")


# In-process application checks ------------------------------------------------------------------------


def header_problems(headers: Mapping[str, str]) -> list[str]:
    lower = {k.lower(): v for k, v in headers.items()}
    problems = []
    csp = {p.split()[0]: p.split()[1:] for p in lower.get("content-security-policy", "").split(";") if p.strip()}
    if not csp:
        problems.append("Content-Security-Policy missing")
    else:
        if csp.get("script-src") != ["'self'"]:
            problems.append("script-src is not exactly 'self'")
        if any(v in {"'unsafe-inline'", "'unsafe-eval'", "*"} for values in csp.values() for v in values):
            problems.append("CSP allows unsafe-inline, unsafe-eval or *")
        for directive, expected in (
            ("object-src", ["'none'"]),
            ("base-uri", ["'none'"]),
            ("frame-ancestors", ["'none'"]),
        ):
            if csp.get(directive) != expected:
                problems.append(f"{directive} is not 'none'")
        if csp.get("form-action", [""])[0] != "'self'":
            problems.append("form-action does not start with 'self'")
    hsts = lower.get("strict-transport-security", "")
    match = re.search(r"max-age=(\d+)", hsts)
    if not match or int(match.group(1)) < 31536000:
        problems.append("HSTS missing or max-age under one year")
    if "includesubdomains" not in hsts.lower():
        problems.append("HSTS lacks includeSubDomains")
    for name, expected in (
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ):
        if lower.get(name, "").lower() != expected:
            problems.append(f"{name} is not {expected}")
    if lower.get("referrer-policy") not in {
        "no-referrer",
        "strict-origin-when-cross-origin",
        "same-origin",
        "strict-origin",
    }:
        problems.append("Referrer-Policy missing or weak")
    if "permissions-policy" not in lower:
        problems.append("Permissions-Policy missing")
    if re.search(r"\d", lower.get("server", "")) or "x-powered-by" in lower:
        problems.append("a Server or X-Powered-By header reveals a version")
    return problems


def check_app(env: Mapping[str, str], static_dir: Path, workdir: Path, report: Report) -> None:
    """Build the application from ``env`` with a temporary database and probe it in process."""
    import warnings

    with warnings.catch_warnings():  # starlette notes that its test client will move off httpx; irrelevant here
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

    from kestrix.server import app as app_module
    from kestrix.server.app import create_app
    from kestrix.server.auth import ACCESS_COOKIE
    from kestrix.server.hosted import IP_LIMITS, USER_LIMITS
    from kestrix.server.settings import Settings, SettingsError, load_settings

    try:
        loaded = load_settings(dict(env), mode="hosted")
    except SettingsError as exc:
        report.add("settings", FAIL, f"the server would refuse to start: {exc}")
        for skipped in ("app-headers", "health", "private-targets", "auth-gate", "rate-limits"):
            report.add(skipped, SKIP, "settings did not load")
        return
    assert loaded.hosted is not None
    report.add("settings", PASS, "load_settings accepts the configuration (the server would start)")
    hosted = dataclasses.replace(loaded.hosted, db_path=workdir / "app" / "preflight.db")
    previous_static = app_module.STATIC_DIR
    app_module.STATIC_DIR = static_dir
    try:
        app = create_app(server_settings=Settings(mode="hosted", hosted=hosted))
        client = TestClient(app, base_url=hosted.public_origin)

        health = client.get("/api/health")
        body = health.json() if health.headers.get("content-type", "").startswith("application/json") else {}
        ok = health.status_code == 200 and body.get("status") == "ok" and body.get("mode") == "hosted"
        report.add(
            "health",
            PASS if ok else FAIL,
            f"/api/health -> {health.status_code}, mode {body.get('mode')}, modules {body.get('modules')}",
        )
        for label, response in (("page", client.get("/")), ("api", health)):
            problems = header_problems(response.headers)
            report.add(
                f"headers:{label}",
                FAIL if problems else PASS,
                "; ".join(problems)
                or "CSP, HSTS, COOP, CORP, nosniff, Referrer-Policy and Permissions-Policy are correct",
            )
        cache = client.get("/").headers.get("cache-control", "")
        report.add(
            "cache:api",
            PASS if health.headers.get("cache-control") == "no-store" else FAIL,
            f"/api/ responses: {health.headers.get('cache-control')!r}",
        )
        report.add("cache:page", PASS if cache == "no-cache" else FAIL, f"index.html: {cache!r}")
        wrong_host = client.get("/api/health", headers={"host": "preflight-attacker.invalid"})
        report.add(
            "host-allowlist",
            PASS if wrong_host.status_code == 421 else FAIL,
            f"a foreign Host header -> {wrong_host.status_code} (want 421)",
        )

        gate = [
            client.get("/api/webcheck").status_code,
            client.get("/api/detect/cases").status_code,
            client.get("/api/openapi.json").status_code,
        ]
        report.add(
            "auth-gate",
            PASS if gate[0] == 401 and gate[1] == 404 and gate[2] in {401, 404} else FAIL,
            f"signed out: webcheck {gate[0]} (want 401), detect {gate[1]} (want 404), openapi {gate[2]} (want 401 or 404)",
        )

        auth = app.state.auth
        now = int(time.time())
        user = auth.store.upsert_user(
            "preflight", "preflight", "preflight@preflight.invalid", "Preflight", now, terms_accepted=True
        )
        sid, refresh = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        auth.store.create_family(sid, user.id, auth.refresh_hash(refresh), now, now + 3600)
        access, _ = auth.tokens.issue(user.id, sid, now)
        client.cookies.set(ACCESS_COOKIE, access, domain=hosted.public_host)
        write = {"x-csrf-token": auth.csrf_token(sid), "origin": hosted.public_origin}
        statuses = []
        for target in LOCAL_TARGETS:
            response = client.post(
                "/api/webcheck", json={"url": target, "scope": "page", "authorized": True}, headers=write
            )
            statuses.append(
                (response.status_code, response.json().get("reason") if response.status_code != 200 else "scanned")
            )
        refused = all(code in {403, 502} and reason != "scanned" for code, reason in statuses)
        report.add(
            "private-targets",
            PASS if refused else FAIL,
            f"{len(LOCAL_TARGETS)} loopback, link-local and private targets -> {sorted(set(statuses))}",
        )

        report.add(
            "rate-limits:config",
            PASS if USER_LIMITS and IP_LIMITS else FAIL,
            f"{len(USER_LIMITS)} per-user and {len(IP_LIMITS)} per-address limits defined",
        )
        provider = next(iter(hosted.providers))
        limit = IP_LIMITS["/api/auth/login/"][1]
        codes = [
            client.get(f"/api/auth/login/{provider}", follow_redirects=False).status_code for _ in range(limit + 1)
        ]
        report.add(
            "rate-limits:enforced",
            PASS if codes[-1] == 429 and 429 not in codes[:-1] else FAIL,
            f"sign-in start: request {limit + 1} -> {codes[-1]} (want 429 after {limit})",
        )
    finally:
        app_module.STATIC_DIR = previous_static


def check_live(url: str, report: Report, fetch: Callable[[str], tuple[int, Mapping[str, str]]] | None = None) -> None:
    import httpx

    def default(target: str) -> tuple[int, Mapping[str, str]]:
        response = httpx.get(target, timeout=10.0, follow_redirects=False)
        return response.status_code, dict(response.headers)

    get = fetch or default
    base = url.rstrip("/")
    try:
        status, headers = get(f"{base}/api/health")
        page_status, page_headers = get(f"{base}/")
    except Exception as exc:
        report.add("live", FAIL, f"could not reach {base}: {type(exc).__name__}")
        return
    report.add("live:health", PASS if status == 200 else FAIL, f"{base}/api/health -> {status}")
    for label, got in (("api", headers), ("page", page_headers)):
        problems = header_problems(got)
        report.add(
            f"live:headers:{label}",
            FAIL if problems else PASS,
            "; ".join(problems) or "security headers correct on the live site",
        )
    report.add("live:page", PASS if page_status == 200 else FAIL, f"{base}/ -> {page_status}")


# Entry point --------------------------------------------------------------------------------------------


def run(args: argparse.Namespace, base_env: Mapping[str, str] | None = None) -> Report:
    base_env = os.environ if base_env is None else base_env
    with tempfile.TemporaryDirectory(prefix="kestrix-preflight-") as tmp:
        workdir = Path(tmp)
        env: dict[str, str]
        if args.dry_run:
            env = dry_run_env(workdir)
        else:
            env = {k: v for k, v in base_env.items() if k.startswith(("KESTRIX_", "PORT")) or k == "WEB_CONCURRENCY"}
        report = Report([])
        if args.env_file:
            path = Path(args.env_file)
            if not path.is_file():
                report = Report([])
                report.add("env-file", FAIL, f"{path} not found")
                return report
            mode = stat.S_IMODE(path.stat().st_mode)
            env.update({k: v for k, v in parse_env_file(path).items() if k.startswith("KESTRIX_")})
            report = Report([env.get(name, "") for name in SECRET_VARS])
            report.add(
                "env-file",
                PASS if mode & 0o077 == 0 else FAIL,
                f"{path.name} mode {mode:04o}" + ("" if mode & 0o077 == 0 else ", must be 0600 (it holds secrets)"),
            )
        else:
            report = Report([env.get(name, "") for name in SECRET_VARS])
        report.add(
            "mode",
            PASS if env.get("KESTRIX_MODE", "hosted").lower() == "hosted" else FAIL,
            "hosted mode" if env.get("KESTRIX_MODE", "hosted").lower() == "hosted" else "KESTRIX_MODE must be hosted",
        )
        env["KESTRIX_MODE"] = "hosted"
        check_secrets(env, report)
        check_origin(env, report, dry_run=args.dry_run)
        check_oauth(env, report)
        check_operations(env, report, dry_run=args.dry_run)
        db_value = env.get("KESTRIX_DB", "").strip()
        if db_value:
            check_database(Path(db_value), report, dry_run=args.dry_run)
        else:
            report.add(
                "KESTRIX_DB", FAIL, "not set; set it to a path on the persistent volume (for example /data/kestrix.db)"
            )
        static_dir = Path(args.static_dir) if args.static_dir else None
        if static_dir is None:
            from kestrix.server.app import STATIC_DIR

            static_dir = STATIC_DIR
        check_bundle(static_dir, report)
        check_app(env, static_dir, workdir, report)
        if args.url:
            check_live(args.url, report)
    return report


def render(report: Report, *, as_json: bool) -> str:
    if as_json:
        return json.dumps({"counts": report.counts(), "items": [dataclasses.asdict(i) for i in report.items]}, indent=2)
    width = max((len(i.id) for i in report.items), default=0)
    lines = [f"{i.status:<4} {i.id:<{width}}  {i.message}" for i in report.items]
    counts = report.counts()
    lines.append("")
    lines.append(
        f"{counts[PASS]} passed, {counts[FAIL]} failed, {counts[WARN]} warnings, {counts[SKIP]} skipped: "
        + (
            "NOT READY"
            if report.failed
            else "ready (review the warnings and the owner-only checklist in docs/deploy.md)"
        )
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Go-live preflight for the hosted Kestrix service. Never prints secret values."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="ignore the environment and use a throwaway configuration (for CI)"
    )
    parser.add_argument(
        "--env-file", help="KEY=VALUE file (mode 0600) overlaid on the environment, for example staging.env"
    )
    parser.add_argument("--static-dir", help="the built dashboard (default: the installed package's server/static)")
    parser.add_argument("--url", help="also probe this live https site (two GET requests)")
    parser.add_argument("--json", action="store_true", help="print the items as JSON")
    args = parser.parse_args(argv)
    if args.dry_run and args.env_file:
        parser.error("--dry-run ignores the environment; do not combine it with --env-file")
    report = run(args)
    print(render(report, as_json=args.json))
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
