# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from mail_samples import BODY_SENTINEL, message

from kestrix.mail import api
from kestrix.server.app import body_limit

REPORT_KEYS = {
    "generated_by",
    "schema_version",
    "notice",
    "sha256",
    "subject",
    "from_address",
    "verdict",
    "heuristic_score",
    "findings",
    "counts",
}


def test_upload(client: TestClient) -> None:
    raw = message(headers=[("Reply-To", "pay@other.example")])
    response = client.post("/api/mail/analyze", files={"file": ("msg.eml", raw, "message/rfc822")})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == REPORT_KEYS
    assert body["sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["verdict"] == "suspicious"
    assert body["findings"][0]["id"] == "mail.sender.reply_to_mismatch"
    assert BODY_SENTINEL not in response.text


def test_query_options(client: TestClient) -> None:
    raw = message(
        sender='"PayPal" <a@evil.example>',
        auth=("attacker.example; dmarc=pass", "mx.trusted.example; dmarc=fail"),
    )
    response = client.post(
        "/api/mail/analyze",
        params=[("protected_domain", "paypal.com"), ("trusted_authserv_id", "mx.trusted.example")],
        files={"file": ("msg.eml", raw)},
    )
    assert response.status_code == 200
    assert {f["id"] for f in response.json()["findings"]} == {"mail.sender.display_name_brand", "mail.auth.dmarc_fail"}


def test_invalid_query_option_is_400(client: TestClient) -> None:
    response = client.post(
        "/api/mail/analyze", params={"protected_domain": "not a domain"}, files={"file": ("m.eml", message())}
    )
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_non_message_is_400(client: TestClient) -> None:
    response = client.post("/api/mail/analyze", files={"file": ("m.eml", b"\x00\x01garbage")})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_route_has_a_large_body_cap() -> None:
    assert body_limit("/api/mail/analyze") == 26 * 1024 * 1024
    assert body_limit("/api/mail/analyze") > api.MAX_MESSAGE_BYTES + 64 * 1024


def test_declared_oversized_upload_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_MESSAGE_BYTES", 1000)
    response = client.post("/api/mail/analyze", files={"file": ("big.eml", b"\x00" * 200_000)})
    assert response.status_code == 413
    assert response.json()["reason"] == "input_too_large"


def test_streamed_oversized_upload_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_MESSAGE_BYTES", 1000)

    def body() -> Iterator[bytes]:
        yield b'--x\r\nContent-Disposition: form-data; name="file"; filename="a.eml"\r\n\r\n'
        for _ in range(20):
            yield b"\x00" * 10_000

    response = client.post(
        "/api/mail/analyze", content=body(), headers={"content-type": "multipart/form-data; boundary=x"}
    )
    assert response.status_code == 413
    assert response.json()["reason"] == "input_too_large"


def test_upload_needs_a_file_field(client: TestClient) -> None:
    response = client.post("/api/mail/analyze", files={"other": ("a.eml", message())})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_upload_refuses_extra_form_fields(client: TestClient) -> None:
    response = client.post("/api/mail/analyze", data={"note": "x"}, files={"file": ("a.eml", message())})
    assert response.status_code == 400


def test_upload_must_be_multipart(client: TestClient) -> None:
    response = client.post("/api/mail/analyze", content=message(), headers={"content-type": "message/rfc822"})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_protected_domain_feeds_the_lookalike_analyzer(client: TestClient) -> None:
    raw = message(sender="Billing <billing@paypa1.com>", auth=("mx.example.net; dmarc=pass",))
    response = client.post(
        "/api/mail/analyze", params=[("protected_domain", "paypal.com")], files={"file": ("msg.eml", raw)}
    )
    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert (finding["id"], finding["analyzer"], finding["severity"]) == ("mail.lookalike.domain", "lookalike", "high")
    assert response.json()["verdict"] == "malicious"
