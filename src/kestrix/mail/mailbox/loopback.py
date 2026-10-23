# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""One-shot loopback listener for `kestrix mail connect` (RFC 8252 section 7.3).

It binds 127.0.0.1 on an ephemeral port, accepts exactly one request to `/mail/connect`, hands its
`code` and `state` to the service (which checks the state), and shows a page that repeats nothing from the
request. It is not part of the dashboard server.
"""

from __future__ import annotations

import http.server
import time
import webbrowser
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

from ...core.errors import Reason, Rejected
from .models import Provider, ProviderStatus
from .service import CALLBACK_PATH, MailboxService

TIMEOUT_S = 300
_PAGE = b"<!doctype html><meta charset=utf-8><title>Kestrix</title><p>You can close this tab and return to the terminal.</p>"


class _Result:
    def __init__(self) -> None:
        self.params: dict[str, str] | None = None


def _handler(result: _Result) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            if parts.path != CALLBACK_PATH or result.params is not None:
                self.send_error(404)
                return
            query = parse_qs(parts.query)
            result.params = {k: v[0] for k, v in query.items() if k in {"code", "state", "error"} and v}
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(_PAGE)))
            self.end_headers()
            self.wfile.write(_PAGE)

        def log_message(self, format: str, *args: object) -> None:  # the request line holds the code
            return

    return Handler


def connect_with_loopback(
    service: MailboxService,
    provider: Provider,
    show: Callable[[str], None],
    *,
    open_browser: bool = True,
    timeout_s: float = TIMEOUT_S,
) -> ProviderStatus:
    """Run the sign-in in the user's browser and wait for the redirect. Raises ``Rejected`` on failure."""
    host = "localhost" if provider == "outlook" else "127.0.0.1"
    result = _Result()
    with http.server.HTTPServer(("127.0.0.1", 0), _handler(result)) as server:
        port = server.server_address[1]
        started = service.start(provider, f"http://{host}:{port}{CALLBACK_PATH}", acknowledged=True, binding=None)
        show(f"Opening your browser to sign in. If nothing opens, visit:\n{started.authorize_url}")
        if open_browser:
            webbrowser.open(started.authorize_url)
        deadline = time.monotonic() + timeout_s
        server.timeout = 1
        while result.params is None and time.monotonic() < deadline:
            server.handle_request()
    params = result.params
    if params is None:
        raise Rejected(Reason.TARGET_UNREACHABLE, f"no sign-in arrived within {int(timeout_s)} seconds")
    state = params.get("state", "")
    if "code" not in params:
        service.cancel(state, None)
        raise Rejected(Reason.INVALID_INPUT, "sign-in was refused or cancelled; no mailbox was connected")
    return service.complete(state, params["code"], None)
