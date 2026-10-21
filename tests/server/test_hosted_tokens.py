# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode access tokens (ADR 0007): JWT verification, the 401 reasons, revocation and key rotation."""

import base64
import json
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from kestrix.server.store import Store
from kestrix.server.tokens import key_id

from .hosted_support import ACCESS, JWT_SECRET, ORIGIN, REFRESH, cookie_value, sign_in

PROTECTED = "/api/forensics/url"
KID = key_id(JWT_SECRET.encode())


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture
def signed_in(hosted, providers):
    """The signed-in client and the claims of its real access token."""
    token = cookie_value(sign_in(hosted, providers), ACCESS)
    return hosted, jwt.decode(token, options={"verify_signature": False})


def use(client: TestClient, token: str) -> None:
    client.cookies.set(ACCESS, token, domain="kestrix.example")


def forge(claims: dict, *, key: str = JWT_SECRET, alg: str = "HS256", kid: str | None = KID) -> str:
    headers = {} if kid is None else {"kid": kid}
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


def reason(client: TestClient) -> str | None:
    resp = client.get(PROTECTED)
    if resp.status_code == 404:  # authenticated: the route only takes POST, so GET falls through
        return None
    assert resp.status_code == 401, resp.text
    return resp.json()["reason"]


def test_a_real_token_has_the_documented_header_and_claims(signed_in, clock):
    client, claims = signed_in
    token = client.cookies.get(ACCESS)
    assert jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT", "kid": KID}
    now = int(clock.now)
    assert claims["iss"] == ORIGIN and claims["aud"] == "kestrix" and claims["sub"].isdigit()
    assert (claims["iat"], claims["nbf"], claims["exp"]) == (now, now, now + 900)
    assert len(claims["sid"]) >= 32 and len(claims["jti"]) >= 22
    assert reason(client) is None
    assert client.get("/api/auth/me").json()["signed_in"]


def test_a_forged_signature_is_refused(signed_in):
    client, _ = signed_in
    header, payload, signature = client.cookies.get(ACCESS).split(".")
    use(client, f"{header}.{payload}.{signature[:-2]}AA")
    assert reason(client) == "sign_in_required"


def test_a_token_signed_with_another_secret_is_refused(signed_in):
    client, claims = signed_in
    use(client, forge(claims, key="another-secret-" + "z" * 40))
    assert reason(client) == "sign_in_required"


def test_alg_none_is_refused(signed_in):
    client, claims = signed_in
    header = b64(json.dumps({"alg": "none", "typ": "JWT", "kid": KID}).encode())
    use(client, f"{header}.{b64(json.dumps(claims).encode())}.")
    assert reason(client) == "sign_in_required"


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")  # the attacker's token, not ours
def test_hs512_with_the_right_secret_is_refused(signed_in):
    client, claims = signed_in
    use(client, forge(claims, alg="HS512"))
    assert reason(client) == "sign_in_required"


@pytest.mark.parametrize("kid", [None, "0123456789abcdef", ""])
def test_a_missing_or_unknown_kid_is_refused(signed_in, kid):
    client, claims = signed_in
    use(client, forge(claims, kid=kid))
    assert reason(client) == "sign_in_required"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://evil.example"},
        {"aud": "someone-else"},
        {"sub": "999999"},  # not the user of this family
        {"sub": "not-a-number"},
        {"sid": "no-such-family"},
        {"exp": "soon"},
    ],
)
def test_wrong_claims_are_refused(signed_in, change):
    client, claims = signed_in
    use(client, forge({**claims, **change}))
    assert reason(client) == "sign_in_required"


@pytest.mark.parametrize("missing", ["exp", "iat", "nbf", "iss", "aud", "sub", "sid", "jti"])
def test_every_claim_is_required(signed_in, missing):
    client, claims = signed_in
    use(client, forge({k: v for k, v in claims.items() if k != missing}))
    assert reason(client) == "sign_in_required"


def test_an_expired_token_is_token_expired(signed_in, clock):
    client, _ = signed_in
    clock.advance(900 + 31)
    resp = client.get(PROTECTED)
    assert resp.status_code == 401
    assert resp.json() == {
        "reason": "token_expired",
        "detail": "your sign-in needs refreshing; call POST /api/auth/refresh",
    }


def test_a_missing_access_token_is_token_expired_only_with_a_refresh_cookie(signed_in):
    client, _ = signed_in
    client.cookies.delete(ACCESS, domain="kestrix.example")
    assert reason(client) == "token_expired"
    client.cookies.delete(REFRESH, domain="kestrix.example")
    assert reason(client) == "sign_in_required"


def test_expiry_and_not_before_allow_30_seconds_of_leeway(signed_in, clock):
    client, claims = signed_in
    clock.advance(900 + 29)
    assert reason(client) is None  # 29 s past exp
    now = int(clock.now)
    use(client, forge({**claims, "nbf": now + 29, "iat": now + 29, "exp": now + 900}))
    assert reason(client) is None
    use(client, forge({**claims, "nbf": now + 31, "iat": now, "exp": now + 900}))
    assert reason(client) == "sign_in_required"
    use(client, forge({**claims, "nbf": now, "iat": now + 31, "exp": now + 900}))
    assert reason(client) == "sign_in_required"
    use(client, forge({**claims, "iat": now - 900, "nbf": now - 900, "exp": now - 31}))
    assert reason(client) == "token_expired"


def test_revocation_from_another_process_applies_within_30_seconds(signed_in, clock, hosted_env):
    client, claims = signed_in
    assert reason(client) is None  # the family is now cached as live
    other = Store(Path(hosted_env["KESTRIX_DB"]))  # say, an operator command
    other.revoke_family(claims["sid"], int(clock.now))
    other.close()
    clock.advance(29)
    assert reason(client) is None  # still within the cache's 30 seconds
    clock.advance(2)
    assert reason(client) == "sign_in_required"


def test_key_rotation(signed_in, make_hosted, providers):
    client, _ = signed_in
    old_token = client.cookies.get(ACCESS)
    new_secret = "rotated-jwt-secret-" + "n" * 40
    rotated = make_hosted(jwt_secret=new_secret.encode(), jwt_secret_previous=JWT_SECRET.encode())
    use(rotated, old_token)
    assert reason(rotated) is None  # the previous key still verifies
    fresh = cookie_value(sign_in(rotated, providers), ACCESS)
    assert jwt.get_unverified_header(fresh)["kid"] == key_id(new_secret.encode()) != KID
    jwt.decode(fresh, new_secret, algorithms=["HS256"], audience="kestrix")  # signed with the current key
    retired = make_hosted(jwt_secret=new_secret.encode())
    use(retired, old_token)
    assert reason(retired) == "sign_in_required"
