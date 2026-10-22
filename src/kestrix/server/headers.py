# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Response headers every Kestrix response carries, in both modes (docs/security-model.md).

The built dashboard has no inline script and no ``eval``, so scripts load only from this origin
(``script-src 'self'``) and no inline style (``style-src 'self'``; React sets styles through the
CSSOM, which the policy allows). Neither directive has ``'unsafe-inline'``. The policy allows no
other origin for any fetch, frame, form or plugin; the sign-in providers are reached by a
top-level link and redirect, which ``connect-src`` and ``form-action 'self'`` do not govern.
``tests/server/test_site_hardening.py`` checks that the built dashboard has no inline code.
"""

from __future__ import annotations

CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
        "object-src 'none'",
        "frame-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    )
)
# Hosted only: a stray http:// sub-resource is upgraded rather than loaded in the clear.
HOSTED_CSP = f"{CSP}; upgrade-insecure-requests"
# Nothing on the site uses these features; the empty allowlist turns them off for the page and its frames.
PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "autoplay",
        "bluetooth",
        "camera",
        "display-capture",
        "geolocation",
        "gyroscope",
        "hid",
        "magnetometer",
        "microphone",
        "midi",
        "payment",
        "publickey-credentials-get",
        "serial",
        "usb",
        "xr-spatial-tracking",
    )
)
HSTS = "max-age=63072000; includeSubDomains"
HSTS_PRELOAD = f"{HSTS}; preload"
# Files under /assets/ carry a content hash in their name, so a changed file is a new URL.
IMMUTABLE = "public, max-age=31536000, immutable"
# Everything else the dashboard serves (index.html, favicon) is revalidated with its ETag.
REVALIDATE = "no-cache"
NO_STORE = {"Cache-Control": "no-store"}

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": PERMISSIONS_POLICY,
}


def hosted_headers(*, hsts_preload: bool = False) -> dict[str, str]:
    """The hosted service's headers: HSTS (preload only when the owner opted in) and the upgrade directive."""
    return {
        **SECURITY_HEADERS,
        "Content-Security-Policy": HOSTED_CSP,
        "Strict-Transport-Security": HSTS_PRELOAD if hsts_preload else HSTS,
    }
