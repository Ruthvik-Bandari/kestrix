# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-918): Webhook tester posts to whatever URL the user saved."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.post("/webhooks/test")
def test_webhook():
    payload = request.get_json()
    target = payload.get("callback_url")
    resp = requests.post(target, json={"event": "ping"}, timeout=5)
    return {"status": resp.status_code}
