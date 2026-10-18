"""Pure evaluators for response headers, cookies and TLS results (no network access)."""

from __future__ import annotations

import re
from collections.abc import Callable

from .models import Finding, Severity, TlsInfo
from .profile import SiteProfile

Headers = dict[str, list[str]]  # lower-cased name -> every value received

HSTS_MIN_AGE = 15_552_000  # 180 days
HSTS_PRELOAD_AGE = 31_536_000  # one year, the hstspreload.org minimum
CERT_EXPIRY_WARN_DAYS = 14
_EVIDENCE_CHARS = 200
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.I)
_VERSION = re.compile(r"\d+\.\d+")


def _ev(text: str) -> str:
    return text if len(text) <= _EVIDENCE_CHARS else text[: _EVIDENCE_CHARS - 1] + "…"


def _one(headers: Headers, name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def check_https(final_scheme: str) -> list[Finding]:
    if final_scheme == "https":
        return []
    return [
        Finding(
            id="https.not_used",
            severity="high",
            title="Site is served over plain HTTP",
            explanation="Traffic can be read or changed by anyone on the network path, including passwords and session cookies.",
            recommendation="Serve the site over HTTPS (free certificates are available from Let's Encrypt) and redirect HTTP to HTTPS.",
        )
    ]


def check_hsts(headers: Headers, https: bool) -> list[Finding]:
    if not https:
        return []
    value = _one(headers, "strict-transport-security")
    if value is None:
        return [
            Finding(
                id="hsts.missing",
                severity="medium",
                title="HSTS header missing",
                explanation="Without Strict-Transport-Security, a browser's first visit can be downgraded to HTTP by an attacker.",
                recommendation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        ]
    match = _MAX_AGE.search(value)
    max_age = int(match.group(1)) if match else None
    if max_age == 0:
        return [
            Finding(
                id="hsts.disabled",
                severity="medium",
                title="HSTS is switched off (max-age=0)",
                explanation="max-age=0 tells browsers to forget the HTTPS-only rule, the same as sending no HSTS header.",
                recommendation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                evidence=_ev(value),
            )
        ]
    out = []
    if max_age is None or max_age < HSTS_MIN_AGE:
        out.append(
            Finding(
                id="hsts.short_max_age",
                severity="low",
                title="HSTS max-age is short",
                explanation="A short max-age lets the browser forget the HTTPS-only rule quickly.",
                recommendation="Use a max-age of at least 15552000 (180 days); 31536000 is common.",
                evidence=_ev(value),
            )
        )
    directives = {d.strip().lower() for d in value.split(";")}
    if "includesubdomains" not in directives:
        out.append(
            Finding(
                id="hsts.no_subdomains",
                severity="info",
                title="HSTS does not cover subdomains",
                explanation="Subdomains can still be reached over HTTP and used to attack cookies of the main site.",
                recommendation="Add includeSubDomains once every subdomain supports HTTPS.",
                evidence=_ev(value),
            )
        )
    elif "preload" not in directives or max_age is None or max_age < HSTS_PRELOAD_AGE:
        out.append(
            Finding(
                id="hsts.not_preload_ready",
                severity="info",
                title="HSTS is not ready for the preload list",
                explanation="Preloaded sites are HTTPS-only from the very first visit. That needs a max-age of at least "
                "one year, includeSubDomains and preload.",
                recommendation="If every subdomain is HTTPS-only, add 'preload' and submit the domain at hstspreload.org.",
                evidence=_ev(value),
            )
        )
    return out


def _csp_directives(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp_policies(headers: Headers) -> list[dict[str, list[str]]]:
    """Every enforced policy. Several headers, or comma-separated policies in one header, are all
    enforced by the browser, so a weakness counts only when every policy has it."""
    return [_csp_directives(p) for v in headers.get("content-security-policy", []) for p in v.split(",") if p.strip()]


def _script_sources(policy: dict[str, list[str]]) -> list[str] | None:
    """Effective script sources, or None when the policy does not restrict scripts at all."""
    for name in ("script-src", "default-src"):
        if name in policy:
            return policy[name]
    return None


def _nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)


def _inline_allowed(p: dict[str, list[str]]) -> bool:
    # With a nonce or hash present, CSP Level 2+ browsers ignore 'unsafe-inline'.
    src = _script_sources(p) or []
    return "'unsafe-inline'" in src and not _nonce_or_hash(src)


def _eval_allowed(p: dict[str, list[str]]) -> bool:
    return "'unsafe-eval'" in (_script_sources(p) or [])


def _any_host_allowed(p: dict[str, list[str]]) -> bool:
    # 'strict-dynamic' makes browsers ignore host and scheme sources.
    src = _script_sources(p) or []
    return "'strict-dynamic'" not in src and any(s in {"*", "http:", "https:", "data:"} for s in src)


def _plugins_allowed(p: dict[str, list[str]]) -> bool:
    return p.get("object-src", p.get("default-src")) != ["'none'"]


_CSP_WEAKNESSES: tuple[tuple[Callable[[dict[str, list[str]]], bool], str, Severity, str, str, str], ...] = (
    (
        _inline_allowed,
        "csp.unsafe_inline",
        "low",
        "CSP allows inline scripts",
        "'unsafe-inline' lets injected <script> tags run, which removes most of CSP's XSS protection.",
        "Use nonces or hashes for the inline scripts you need and drop 'unsafe-inline'.",
    ),
    (
        _eval_allowed,
        "csp.unsafe_eval",
        "low",
        "CSP allows eval()",
        "'unsafe-eval' lets strings be executed as code, a common XSS escalation path.",
        "Remove 'unsafe-eval' and replace eval-style code.",
    ),
    (
        _any_host_allowed,
        "csp.wildcard_source",
        "low",
        "CSP allows scripts from any host",
        "A wildcard or bare scheme source lets scripts load from attacker-controlled servers.",
        "List the exact hosts that serve your scripts, or use nonces with 'strict-dynamic'.",
    ),
    (
        _plugins_allowed,
        "csp.object_src_open",
        "low",
        "CSP does not block plugins",
        "Without object-src 'none' (or default-src 'none'), <object> and <embed> can load content that runs script.",
        "Add \"object-src 'none'\".",
    ),
    (
        lambda p: "base-uri" not in p,
        "csp.base_uri_missing",
        "info",
        "CSP does not restrict <base>",
        "An injected <base> tag can redirect relative script URLs, which bypasses nonce-based policies.",
        "Add \"base-uri 'none'\" (or 'self').",
    ),
)


def check_csp(headers: Headers) -> list[Finding]:
    """Grade what the enforced CSP actually restricts, not just whether one is present."""
    policies = _csp_policies(headers)
    if not policies:
        report_only = _one(headers, "content-security-policy-report-only")
        if report_only is not None:
            return [
                Finding(
                    id="csp.report_only",
                    severity="medium",
                    title="CSP is in report-only mode",
                    explanation="Content-Security-Policy-Report-Only only reports violations; the browser still runs injected scripts.",
                    recommendation="Once the reports are clean, send the same policy as Content-Security-Policy.",
                    evidence=_ev(report_only),
                )
            ]
        return [
            Finding(
                id="csp.missing",
                severity="medium",
                title="Content-Security-Policy missing",
                explanation="A CSP limits which scripts may run, which greatly reduces the impact of cross-site scripting (XSS).",
                recommendation="Start with \"default-src 'self'; object-src 'none'; base-uri 'none'\" and tighten from there.",
            )
        ]
    evidence = _ev(", ".join(headers["content-security-policy"]))
    if all(_script_sources(p) is None for p in policies):
        # Scripts are unrestricted, so the per-source checks below do not apply.
        return [
            Finding(
                id="csp.no_script_restriction",
                severity="medium",
                title="CSP does not restrict scripts",
                explanation="The policy has neither script-src nor default-src, so injected scripts still run. It may "
                "control framing or other resources, but it gives no protection against XSS.",
                recommendation="Add a script-src, ideally nonce-based: \"script-src 'nonce-<random>' 'strict-dynamic'; "
                "object-src 'none'; base-uri 'none'\".",
                evidence=evidence,
            )
        ]
    return [
        Finding(id=fid, severity=sev, title=title, explanation=why, recommendation=fix, evidence=evidence)
        for weak, fid, sev, title, why, fix in _CSP_WEAKNESSES
        if all(weak(p) for p in policies)
    ]


def check_framing(headers: Headers) -> list[Finding]:
    xfo = (_one(headers, "x-frame-options") or "").strip().upper()
    if xfo in {"DENY", "SAMEORIGIN"} or any("frame-ancestors" in p for p in _csp_policies(headers)):
        return []
    return [
        Finding(
            id="framing.unprotected",
            severity="medium",
            title="Page can be embedded by other sites",
            explanation="Without X-Frame-Options or CSP frame-ancestors, attackers can overlay your page to trick clicks (clickjacking).",
            recommendation="Send \"Content-Security-Policy: frame-ancestors 'self'\" (or X-Frame-Options: DENY).",
        )
    ]


def check_simple_headers(headers: Headers) -> list[Finding]:
    out = []
    if (_one(headers, "x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(
            Finding(
                id="xcto.missing",
                severity="low",
                title="X-Content-Type-Options missing",
                explanation="Browsers may guess content types and run an uploaded file as script.",
                recommendation="Send 'X-Content-Type-Options: nosniff'.",
            )
        )
    referrer = _one(headers, "referrer-policy")
    if referrer is None or referrer.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
        out.append(
            Finding(
                id="referrer.weak",
                severity="low",
                title="Referrer-Policy missing or permissive",
                explanation="Full URLs, which can contain tokens or personal data, may leak to other sites.",
                recommendation="Send 'Referrer-Policy: strict-origin-when-cross-origin' (or no-referrer).",
                evidence=_ev(referrer) if referrer else None,
            )
        )
    if _one(headers, "permissions-policy") is None:
        out.append(
            Finding(
                id="permissions_policy.missing",
                severity="info",
                title="Permissions-Policy missing",
                explanation="Embedded content may request powerful browser features such as camera or geolocation.",
                recommendation="Disable features you do not use, e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            )
        )
    if _one(headers, "cross-origin-opener-policy") is None:
        out.append(
            Finding(
                id="coop.missing",
                severity="info",
                title="Cross-Origin-Opener-Policy missing",
                explanation="Other windows you open can keep a reference to your page, enabling some cross-site leaks.",
                recommendation="Send 'Cross-Origin-Opener-Policy: same-origin' if the site does not rely on cross-origin popups.",
            )
        )
    return out


def check_disclosure(headers: Headers) -> list[Finding]:
    out = []
    server = _one(headers, "server")
    if server and _VERSION.search(server):
        out.append(
            Finding(
                id="disclosure.server_version",
                severity="low",
                title="Server header reveals software version",
                explanation="Exact versions help attackers pick known exploits.",
                recommendation="Remove the version from the Server header (e.g. nginx 'server_tokens off').",
                evidence=_ev(server),
            )
        )
    powered = _one(headers, "x-powered-by")
    if powered:
        out.append(
            Finding(
                id="disclosure.powered_by",
                severity="low",
                title="X-Powered-By header present",
                explanation="It advertises the framework and often its version.",
                recommendation="Remove the X-Powered-By header.",
                evidence=_ev(powered),
            )
        )
    return out


def _cookie_attrs(raw: str) -> tuple[str, dict[str, str]]:
    name = raw.split("=", 1)[0].strip()
    attrs = {}
    for part in raw.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        attrs[key.lower()] = value.strip().lower()
    return name, attrs


def check_cookies(headers: Headers, https: bool) -> list[Finding]:
    out = []
    for raw in headers.get("set-cookie", []):
        name, attrs = _cookie_attrs(raw)
        evidence = f"cookie {name!r}"  # never echo cookie values
        if https and "secure" not in attrs:
            out.append(
                Finding(
                    id="cookie.no_secure",
                    severity="medium",
                    title=f"Cookie {name} lacks Secure",
                    explanation="The cookie can be sent over plain HTTP and intercepted.",
                    recommendation="Add the Secure attribute.",
                    evidence=evidence,
                )
            )
        if "httponly" not in attrs:
            out.append(
                Finding(
                    id="cookie.no_httponly",
                    severity="low",
                    title=f"Cookie {name} lacks HttpOnly",
                    explanation="Scripts can read the cookie, so an XSS bug could steal it. Fine only if JavaScript must read it.",
                    recommendation="Add HttpOnly to session and authentication cookies.",
                    evidence=evidence,
                )
            )
        prefix = name.lower()  # browsers now match the prefixes case-insensitively
        if prefix.startswith(("__host-", "__secure-")) and (
            "secure" not in attrs or (prefix.startswith("__host-") and ("domain" in attrs or attrs.get("path") != "/"))
        ):
            out.append(
                Finding(
                    id="cookie.prefix_violation",
                    severity="medium",
                    title=f"Cookie {name} breaks its name-prefix rules",
                    explanation="Browsers drop a __Secure- cookie without Secure, and a __Host- cookie without Secure, "
                    "with a Domain, or with a Path other than /.",
                    recommendation="Set Secure, and for __Host- also Path=/ and no Domain attribute.",
                    evidence=evidence,
                )
            )
        samesite = attrs.get("samesite")
        if samesite is None:
            out.append(
                Finding(
                    id="cookie.no_samesite",
                    severity="low",
                    title=f"Cookie {name} has no SameSite",
                    explanation="Browsers apply defaults that vary; explicit SameSite limits cross-site request forgery.",
                    recommendation="Add SameSite=Lax (or Strict).",
                    evidence=evidence,
                )
            )
        elif samesite == "none" and "secure" not in attrs:
            out.append(
                Finding(
                    id="cookie.samesite_none_insecure",
                    severity="medium",
                    title=f"Cookie {name} is SameSite=None without Secure",
                    explanation="Browsers reject or downgrade such cookies, and they travel with every cross-site request.",
                    recommendation="Add Secure, or use SameSite=Lax.",
                    evidence=evidence,
                )
            )
    return out


_TLS_TEXT = {
    "expired": ("The certificate has expired", "Renew the certificate; enable automatic renewal."),
    "not_yet_valid": ("The certificate is not valid yet", "Check the server clock and the certificate's start date."),
    "hostname_mismatch": (
        "The certificate does not match this hostname",
        "Issue a certificate that lists this exact hostname.",
    ),
    "untrusted": ("The certificate is not trusted", "Use a certificate from a public CA and serve the full chain."),
    "outdated_protocol": ("The server only offers TLS older than 1.2", "Enable TLS 1.2 and 1.3; disable TLS 1.0/1.1."),
    "handshake_failed": ("The TLS handshake failed", "Check the server's TLS configuration."),
}


def check_tls(tls: TlsInfo) -> list[Finding]:
    if tls.status == "not_https":
        return []
    if tls.status != "ok":
        title, fix = _TLS_TEXT[tls.status]
        return [
            Finding(
                id=f"tls.{tls.status}",
                severity="high",
                title=title,
                explanation="Browsers show a security warning, and users who click through can be intercepted.",
                recommendation=fix,
                evidence=_ev(tls.detail) if tls.detail else None,
            )
        ]
    if tls.days_remaining is not None and tls.days_remaining < CERT_EXPIRY_WARN_DAYS:
        return [
            Finding(
                id="tls.expiring_soon",
                severity="medium",
                title=f"Certificate expires in {tls.days_remaining} days",
                explanation="An expired certificate makes the site unreachable for most users.",
                recommendation="Renew now and automate renewal.",
                evidence=tls.not_after,
            )
        ]
    return []


def evaluate(headers: Headers, final_scheme: str, tls: TlsInfo) -> list[Finding]:
    https = final_scheme == "https"
    return (
        check_https(final_scheme)
        + check_tls(tls)
        + check_hsts(headers, https)
        + check_cookies(headers, https)
        + check_csp(headers)
        + check_framing(headers)
        + check_simple_headers(headers)
        + check_disclosure(headers)
    )


# Severity by site profile, for findings whose risk depends on what the site does. A missing
# entry keeps the checklist severity. Entries only ever lower severity, and only with evidence.
_BY_PROFILE: dict[str, dict[str, Severity]] = {
    "csp.missing": {"static": "low"},
    "csp.report_only": {"static": "low"},
    "csp.no_script_restriction": {"static": "low"},
    "framing.unprotected": {"static": "info", "static_api": "low"},
    "referrer.weak": {"static": "info"},
}
_KIND_TEXT = {"static": "static site", "static_api": "static site with a backend", "dynamic": "dynamic site"}
_CSP_IDS = frozenset({"csp.missing", "csp.report_only", "csp.no_script_restriction"})
_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}


def apply_profile(findings: list[Finding], profile: SiteProfile) -> list[Finding]:
    """Re-weigh context-dependent findings for the site profile, recording the original severity."""
    out = []
    why = "; ".join(profile.reasons)
    for f in findings:
        target = _BY_PROFILE.get(f.id, {}).get(profile.kind)
        # Third-party scripts are exactly what a CSP constrains, so a static site that loads them keeps the CSP severity.
        if f.id in _CSP_IDS and profile.evidence.third_party_script_hosts:
            target = None
        if target is None or _RANK[target] >= _RANK[f.severity]:
            out.append(f)
            continue
        context = f"{f.severity.capitalize()} on sites with logins or sessions; {target} here, a {_KIND_TEXT[profile.kind]} ({why})."
        out.append(f.model_copy(update={"severity": target, "baseline_severity": f.severity, "context": context}))
    return out
