# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-918): Webhook tester only calls hosts from a fixed allowlist."""

from urllib.parse import urlsplit

import requests
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"hooks.slack.com", "discord.com"}


@app.post("/webhooks/test")
def test_webhook():
    target = request.get_json().get("callback_url", "")
    parts = urlsplit(target)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        abort(400)
    resp = requests.post(f"https://{parts.hostname}{parts.path}", json={"event": "ping"}, timeout=5)
    return {"status": resp.status_code}
