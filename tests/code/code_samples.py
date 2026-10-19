# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Synthetic credentials for scanner tests.

They are assembled at run time so no token-shaped literal sits in the repository (and secret
scanners on the hosting side have nothing to flag). None of them is or was ever valid.
"""

import string

_ALPHABET = string.ascii_letters + string.digits


def noise(length: int, seed: int = 7, alphabet: str = _ALPHABET) -> str:
    """Deterministic, high-entropy characters."""
    return "".join(alphabet[(i * seed + i * i * 3 + seed) % len(alphabet)] for i in range(length))


def fake(kind: str) -> str:
    if kind == "aws_access_key_id":
        return "AKIA" + noise(16, alphabet=string.ascii_uppercase + string.digits)
    if kind == "aws_secret_access_key":
        return noise(40, seed=11)
    if kind == "github_token":
        return "gh" + "p_" + noise(36)
    if kind == "github_pat":
        return "github" + "_pat_" + noise(82, seed=13)
    if kind == "slack_token":
        return "xo" + "xb-" + "4815162342" + "-" + noise(24, seed=5)
    if kind == "stripe_live_key":
        return "sk" + "_live_" + noise(24, seed=17)
    if kind == "google_api_key":
        return "AI" + "za" + noise(35, seed=19)
    if kind == "jwt":
        return "ey" + "J" + noise(20, seed=23) + ".ey" + "J" + noise(30, seed=29) + "." + noise(43, seed=31)
    if kind == "anthropic_api_key":
        return "sk-" + "ant-api03-" + noise(90, seed=37)
    if kind == "openai_api_key":
        return "sk-" + "proj-" + noise(48, seed=41)
    if kind == "generic":
        return noise(24, seed=43) + "!"
    raise ValueError(kind)


def private_key_block() -> str:
    body = "\n".join(noise(64, seed=s, alphabet=string.ascii_letters + string.digits + "+/") for s in (47, 53, 59))
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----\n"
