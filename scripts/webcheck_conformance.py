# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Live conformance run of `kestrix webcheck` against badssl.com's known-broken endpoints.

Run from the repo root: ``uv run python scripts/webcheck_conformance.py``. It makes real network
requests, one scan per endpoint, to badssl.com only (a public service built for this purpose),
so it is not part of the test suite or CI. Exit status is 1 if any endpoint gets an unexpected result.

The header checks are covered offline by ``tests/webcheck`` (``test_conformance_pages``).
"""

from __future__ import annotations

import sys

from kestrix.core.errors import Rejected
from kestrix.webcheck.scan import scan

# endpoint -> (TLS statuses accepted, finding ids that must appear, finding ids that must not appear)
CASES: dict[str, tuple[set[str], set[str], set[str]]] = {
    "https://sha256.badssl.com/": ({"ok"}, set(), {"tls.untrusted", "tls.expired"}),
    "https://expired.badssl.com/": ({"expired"}, {"tls.expired"}, set()),
    "https://wrong.host.badssl.com/": ({"hostname_mismatch"}, {"tls.hostname_mismatch"}, set()),
    "https://self-signed.badssl.com/": ({"untrusted"}, {"tls.untrusted"}, set()),
    "https://untrusted-root.badssl.com/": ({"untrusted"}, {"tls.untrusted"}, set()),
    # A client OpenSSL with TLS 1.0 disabled fails before the version is negotiated.
    "https://tls-v1-0.badssl.com:1010/": (
        {"outdated_protocol", "handshake_failed"},
        set(),
        {"tls.expired", "tls.untrusted"},
    ),
    "http://http.badssl.com/": ({"not_https"}, {"https.not_used"}, set()),
    "https://hsts.badssl.com/": ({"ok"}, set(), {"hsts.missing"}),
}


def main() -> int:
    failures = 0
    for url, (statuses, required, forbidden) in CASES.items():
        try:
            report = scan(url, scope="page")
        except Rejected as exc:
            print(f"FAIL {url}: rejected {exc.reason}: {exc.detail}")
            failures += 1
            continue
        found = {f.id for f in report.findings}
        problems = []
        if report.tls.status not in statuses:
            problems.append(f"tls {report.tls.status}, expected {sorted(statuses)}")
        if missing := required - found:
            problems.append(f"missing {sorted(missing)}")
        if unexpected := forbidden & found:
            problems.append(f"unexpected {sorted(unexpected)}")
        failures += bool(problems)
        status = "FAIL" if problems else "ok  "
        print(
            f"{status} {url}: grade {report.grade}, tls {report.tls.status}"
            + (f" ({'; '.join(problems)})" if problems else "")
        )
    print(f"{len(CASES) - failures}/{len(CASES)} endpoints as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
