import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from forensics_samples import pe_bytes

from kestrix.forensics import api

FILE_KEYS = {
    "generated_by",
    "filename",
    "size",
    "hashes",
    "file_type",
    "entropy",
    "byte_histogram",
    "printable_ratio",
    "exif",
    "exif_status",
    "findings",
}
URL_KEYS = {
    "generated_by",
    "url",
    "scheme",
    "host",
    "unicode_host",
    "registrable_domain",
    "score",
    "level",
    "score_note",
    "findings",
}


def test_file_upload(client: TestClient) -> None:
    data = pe_bytes(b"\x00" * 2000)
    response = client.post("/api/forensics/file", files={"file": ("invoice.pdf", data, "application/pdf")})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == FILE_KEYS
    assert body["filename"] == "invoice.pdf"
    assert body["size"] == len(data)
    assert body["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["file_type"]["id"] == "pe"
    assert body["file_type"]["extension_mismatch"] is True
    assert len(body["byte_histogram"]) == 256
    assert body["exif"] is None
    assert body["exif_status"] == "not_image"
    assert body["findings"][0] == {
        "id": "extension_mismatch",
        "severity": "high",
        "title": "Extension does not match the content",
        "explanation": body["findings"][0]["explanation"],
    }


def test_upload_path_is_reduced_to_a_base_name(client: TestClient) -> None:
    response = client.post("/api/forensics/file", files={"file": ("../../etc/passwd", b"root:x:0:0\n")})
    assert response.status_code == 200
    assert response.json()["filename"] == "passwd"


def test_declared_oversized_upload_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_FILE_BYTES", 1000)
    response = client.post("/api/forensics/file", files={"file": ("big.bin", b"\x00" * 200_000)})
    assert response.status_code == 413
    assert response.json()["reason"] == "input_too_large"


def test_streamed_oversized_upload_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_FILE_BYTES", 1000)

    def body() -> Iterator[bytes]:
        yield b'--x\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        for _ in range(20):
            yield b"\x00" * 10_000

    response = client.post(
        "/api/forensics/file", content=body(), headers={"content-type": "multipart/form-data; boundary=x"}
    )
    assert response.status_code == 413
    assert response.json()["reason"] == "input_too_large"


def test_upload_needs_a_file_field(client: TestClient) -> None:
    response = client.post("/api/forensics/file", files={"other": ("a.txt", b"hello")})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_upload_refuses_extra_form_fields(client: TestClient) -> None:
    response = client.post("/api/forensics/file", data={"note": "x"}, files={"file": ("a.txt", b"hello")})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_upload_must_be_multipart(client: TestClient) -> None:
    response = client.post("/api/forensics/file", json={"file": "x"})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_url_check(client: TestClient) -> None:
    response = client.post("/api/forensics/url", json={"url": "http://192.168.0.1/login"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == URL_KEYS
    assert body["host"] == "192.168.0.1"
    assert body["registrable_domain"] is None
    assert body["level"] == "medium"
    assert {finding["id"] for finding in body["findings"]} == {"ip_address_host", "not_https", "suspicious_keywords"}


def test_invalid_url_is_rejected(client: TestClient) -> None:
    response = client.post("/api/forensics/url", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_url"


def test_oversized_url_is_413(client: TestClient) -> None:
    response = client.post("/api/forensics/url", json={"url": "https://example.com/" + "a" * 10_000})
    assert response.status_code == 413
